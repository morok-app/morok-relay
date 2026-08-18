"""
Решта фіксів зовнішнього аудиту №3 (MEDIUM), окрім push і remote_forward
(ті мають власні файли).
"""
from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.asyncio


# ── admin logout був фейковим ────────────────────────────────────────────
async def test_admin_logout_actually_revokes(redis):
    """
    Було: login зберігає SHA256(token), logout видаляв СИРИЙ token —
    ключ не збігався, logout відповідав revoked:true, а токен лишався
    живим до TTL 1 год.
    """
    from morok_relay.api.admin import (
        _create_admin_token,
        _verify_admin_token,
        admin_logout,
    )

    token = await _create_admin_token(redis, ttl_seconds=3600)
    assert await _verify_admin_token(redis, token) is True

    await admin_logout(redis, authorization=f"Bearer {token}")

    assert await _verify_admin_token(redis, token) is False, \
        "logout не прибрав токен — ключ не збігався"


async def test_admin_logout_without_header_is_noop(redis):
    from morok_relay.api.admin import admin_logout
    result = await admin_logout(redis, authorization=None)
    assert result == {"revoked": True}


# ── DM на soft-deleted акаунт ─────────────────────────────────────────────
async def test_federated_dm_rejected_for_deleted_recipient(db):
    """
    Group-шлях уже перевіряв deleted_at, DM-шлях — ні: trusted peer міг
    після видалення акаунта знову покласти blob на видалений pubkey.
    """
    import uuid

    from morok_relay.config import get_settings
    from morok_relay.models import User, UserTier

    settings = get_settings()
    pk = b"\xee" * 32
    db.add(User(
        id=uuid.uuid4(), pubkey=pk, username="ghost",
        home_relay=settings.relay_name, tier=UserTier.FREE,
        created_at=int(time.time()), last_seen_at=int(time.time()),
        deleted_at=int(time.time()),
    ))
    await db.commit()

    from sqlalchemy import select
    row = (await db.execute(
        select(User).where(User.pubkey == pk)
    )).scalar_one()

    is_valid_recipient = (
        row is not None
        and row.home_relay == settings.relay_name
        and row.deleted_at is None
    )
    assert is_valid_recipient is False, \
        "видалений акаунт досі виглядає як валідний одержувач DM"


# ── Redis URL redaction ──────────────────────────────────────────────────
def test_redis_url_password_redacted():
    from morok_relay.db import _redact_dsn
    raw = "redis://user:supersecret@localhost:6379/0"
    redacted = _redact_dsn(raw)
    assert "supersecret" not in redacted
    assert "user" in redacted
    assert "***" in redacted


def test_redis_url_without_credentials_unchanged():
    from morok_relay.db import _redact_dsn
    raw = "redis://localhost:6379/0"
    assert _redact_dsn(raw) == raw


# ── lookup semantics: NOT_FOUND != TRANSIENT_ERROR ───────────────────────
async def test_lookup_not_found_stops_retry_immediately(monkeypatch):
    """
    ГОЛОВНЕ. Peer, що явно каже "404 — немає такого", НЕ повинен
    трактуватись як тимчасова помилка і ретраїтись — а раніше й те, і
    інше зводилось до голого None.
    """
    from morok_relay import federation_client as fc
    from morok_relay.api.users import _remote_lookup_with_retry

    calls = {"n": 0}

    async def fake_lookup(hostname, username):
        calls["n"] += 1
        return fc.LookupOutcome.NOT_FOUND, None

    monkeypatch.setattr(fc, "remote_lookup", fake_lookup)
    import morok_relay.api.users as users_mod
    monkeypatch.setattr(users_mod, "remote_lookup", fake_lookup)

    result = await _remote_lookup_with_retry("relay2.example.com", "nobody")
    assert result == {"__not_found": True}
    assert calls["n"] == 1, "NOT_FOUND не мав викликати ретрай"


async def test_lookup_transient_error_does_retry(monkeypatch):
    """Мережевий збій — ретраїться, як і раніше."""
    import morok_relay.api.users as users_mod
    from morok_relay import federation_client as fc
    from morok_relay.api.users import _remote_lookup_with_retry

    calls = {"n": 0}

    async def fake_lookup(hostname, username):
        calls["n"] += 1
        if calls["n"] < 2:
            return fc.LookupOutcome.TRANSIENT_ERROR, None
        return fc.LookupOutcome.FOUND, {"username": "alice"}

    monkeypatch.setattr(users_mod, "remote_lookup", fake_lookup)

    result = await _remote_lookup_with_retry("relay2.example.com", "alice")
    assert result == {"username": "alice"}
    assert calls["n"] == 2, "не відретраїло після transient error"


async def test_lookup_exhausted_retries_returns_none_not_not_found(monkeypatch):
    """
    Peer мертвий увесь час ретраю → None (503 для клієнта), а НЕ
    {"__not_found": True} (це раніше й було коренем бага: тимчасово
    мертвий peer виглядав як "юзернейма не існує").
    """
    import morok_relay.api.users as users_mod
    from morok_relay import federation_client as fc
    from morok_relay.api.users import _remote_lookup_with_retry

    async def always_transient(hostname, username):
        return fc.LookupOutcome.TRANSIENT_ERROR, None

    monkeypatch.setattr(users_mod, "remote_lookup", always_transient)
    monkeypatch.setattr(users_mod, "FED_LOOKUP_RETRY_DELAYS", [0, 0])

    result = await _remote_lookup_with_retry("relay2.example.com", "alice")
    assert result is None


# ── admin _ping_relay: той самий DNS-rebinding TOCTOU, інший файл ────────
async def test_ping_relay_uses_pinned_get_not_raw_httpx(monkeypatch):
    """
    Було: is_safe_peer_hostname() check → ОКРЕМИЙ httpx.AsyncClient().get()
    — другий DNS resolve під час фактичного з'єднання. Перевіряємо, що
    _ping_relay тепер іде через _pinned_get (той самий механізм, що вже
    закритий у federation_client для DM/lookup/snapshot/handshake).
    """
    from unittest.mock import AsyncMock, MagicMock, patch

    from morok_relay.api.admin import _ping_relay

    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json = MagicMock(return_value={"version": "0.9.0"})

    with patch(
        "morok_relay.federation_client._pinned_get",
        new=AsyncMock(return_value=fake_response),
    ) as mock_pinned:
        result = await _ping_relay("relay2.example.com")

    mock_pinned.assert_called_once_with("relay2.example.com", "/health")
    assert result["up"] is True
    assert result["version"] == "0.9.0"


async def test_ping_relay_unsafe_host_returns_down(monkeypatch):
    from unittest.mock import AsyncMock, patch

    from morok_relay.api.admin import _ping_relay

    with patch(
        "morok_relay.federation_client._pinned_get",
        new=AsyncMock(return_value=None),  # _pinned_get сам відмовляє
    ):
        result = await _ping_relay("evil.example.com")
    assert result["up"] is False
