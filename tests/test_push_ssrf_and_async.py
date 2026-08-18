"""
Web push: SSRF endpoint + DoS-amplifier (аудит зовн. №3, HIGH).

Знахідка: /push/subscribe приймав endpoint як довільний рядок без
перевірки схеми/host, без rate-limit, без ліміту кількості підписок.
pywebpush пізніше б'є на цей URL реальним HTTP POST — залогінений
користувач міг змусити релей стукати куди завгодно (blind SSRF),
і накопичити необмежену кількість підписок, кожна з яких множить
трафік на КОЖНУ вхідну push-подію.

Друга половина того самого HIGH: `await trigger_push(...)` стояв на
critical path запиту попри власний докстрінг "caller must never await
this" — schedule_push() тепер справді не блокує.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from morok_relay.api.push import PushSubscribeRequest

pytestmark = pytest.mark.asyncio


def _body(endpoint: str) -> dict:
    return dict(
        endpoint=endpoint,
        keys={"p256dh": "a" * 20, "auth": "b" * 20},
    )


# ── схема: allowlist хостів ──────────────────────────────────────────────
def test_known_push_providers_accepted():
    good = [
        "https://updates.push.services.mozilla.com/wpush/v2/abc",
        "https://fcm.googleapis.com/fcm/send/xyz",
        "https://android.googleapis.com/gcm/send/xyz",
        "https://web.push.apple.com/v1/abc",
        "https://xyz.notify.windows.com/w/abc",
    ]
    for ep in good:
        req = PushSubscribeRequest(**_body(ep))
        assert req.endpoint == ep


def test_arbitrary_host_rejected():
    """ГОЛОВНИЙ ТЕСТ. Довільний хост — не «ще один провайдер», а SSRF."""
    bad = [
        "https://evil.example.com/collect",
        "https://internal.local/admin",
        "https://169.254.169.254/latest/meta-data",
        "https://127.0.0.1:6379/",
        "https://fcm.googleapis.com.evil.com/fake",  # suffix-spoofing спроба
    ]
    for ep in bad:
        with pytest.raises(ValidationError):
            PushSubscribeRequest(**_body(ep))


def test_non_https_rejected():
    for ep in (
        "http://fcm.googleapis.com/fcm/send/xyz",
        "ftp://fcm.googleapis.com/x",
        "file:///etc/passwd",
        "javascript:alert(1)",
    ):
        with pytest.raises(ValidationError):
            PushSubscribeRequest(**_body(ep))


def test_malformed_url_rejected():
    for ep in ("not a url", "", "   ", "https://"):
        with pytest.raises(ValidationError):
            PushSubscribeRequest(**_body(ep))


# ── ендпоінт: rate-limit + квота ─────────────────────────────────────────
async def test_subscribe_rate_limited(redis, db, monkeypatch):
    from morok_relay.api.push import post_subscribe
    from morok_relay.config import get_settings
    from morok_relay.sessions import Session

    session = Session(token="t" * 64, pubkey_hex="aa" * 32, expires_at=2**31)
    settings = get_settings()
    monkeypatch.setattr(settings, "vapid_public_key_b64", "dGVzdA==")

    ok = 0
    for i in range(15):
        try:
            await post_subscribe(
                PushSubscribeRequest(**_body(
                    f"https://fcm.googleapis.com/fcm/send/{i}"
                )),
                session, db, redis,
            )
            ok += 1
        except Exception as e:
            from fastapi import HTTPException
            if isinstance(e, HTTPException) and e.status_code == 429:
                break
            raise
    assert ok <= 10, "rate limit не спрацював"


async def test_subscribe_quota_enforced(redis, db, monkeypatch):
    from fastapi import HTTPException

    from morok_relay.api.push import (
        MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT,
        post_subscribe,
    )
    from morok_relay.config import get_settings
    from morok_relay.sessions import Session

    settings = get_settings()
    monkeypatch.setattr(settings, "vapid_public_key_b64", "dGVzdA==")

    session = Session(token="t" * 64, pubkey_hex="bb" * 32, expires_at=2**31)

    # Ізолюємо квоту від rate-limit (10/хв): накидаємо рядки напряму в
    # БД замість проходження через ендпоінт по колу.
    from morok_relay.models import PushSubscription
    now = 0
    for i in range(MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT):
        db.add(PushSubscription(
            pubkey=bytes.fromhex("bb" * 32),
            endpoint=f"https://fcm.googleapis.com/fcm/send/pre{i}",
            p256dh="a" * 20, auth="b" * 20,
            created_at=now, updated_at=now,
        ))
    await db.commit()

    with pytest.raises(HTTPException) as exc_info:
        await post_subscribe(
            PushSubscribeRequest(**_body(
                "https://fcm.googleapis.com/fcm/send/one_too_many"
            )),
            session, db, redis,
        )
    assert exc_info.value.status_code == 409


# ── schedule_push: fire-and-forget, власна сесія ─────────────────────────
async def test_schedule_push_returns_immediately(redis, monkeypatch):
    """
    schedule_push() не має чекати на мережу. Мокаємо саме внутрішню
    _run_push_in_own_session (яка обгортає trigger_push + власну db-
    сесію) повільною функцією і перевіряємо, що виклик повертається
    негайно.
    """
    import asyncio

    from morok_relay import push_sender

    async def slow(*a, **kw):
        await asyncio.sleep(2)

    monkeypatch.setattr(push_sender, "_run_push_in_own_session", slow)

    import time as _time
    t0 = _time.perf_counter()
    push_sender.schedule_push(redis, ["cc" * 32], sender_username=None)
    elapsed = _time.perf_counter() - t0
    assert elapsed < 0.05, "schedule_push заблокував викликача"

    await asyncio.sleep(2.1)


async def test_schedule_push_does_not_use_request_scoped_db(redis, monkeypatch):
    """
    КРИТИЧНО: фонова задача НЕ має отримувати db ззовні — той db
    request-scoped і закривається одразу після відповіді. Перевіряємо,
    що signature schedule_push більше не приймає db-параметр.
    """
    import inspect

    from morok_relay.push_sender import schedule_push
    sig = inspect.signature(schedule_push)
    assert "db" not in sig.parameters, \
        "schedule_push знову приймає db — ризик роботи із закритою сесією"


async def test_background_push_error_is_logged_not_swallowed_silently(
    redis, monkeypatch, caplog,
):
    """
    Помилка у фоновій задачі не має мовчки провалюватись в event loop —
    _log_push_task_error() її ловить і логує.
    """
    import asyncio
    import logging

    from morok_relay import push_sender

    async def boom(*a, **kw):
        raise RuntimeError("simulated push failure")

    monkeypatch.setattr(push_sender, "_run_push_in_own_session", boom)

    with caplog.at_level(logging.WARNING):
        push_sender.schedule_push(redis, ["dd" * 32], sender_username=None)
        await asyncio.sleep(0.1)

    assert any("Background push task failed" in r.message for r in caplog.records)
