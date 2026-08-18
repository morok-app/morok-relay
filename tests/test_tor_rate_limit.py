"""
Tor-aware rate limiting (аудит зовн. №3, HIGH).

Знахідка: усі onion-клієнти діляться одним ідентифікатором "tor" —
навмисно, бо з нашого боку в них немає осмисленої IP-адреси. Але
наслідок: один зловмисний Tor-клієнт міг вичерпати auth_challenge/
auth_verify/backup_restore для ВСІХ Tor-користувачів одночасно.

Фікс — два незалежні шари: підвищена глобальна стеля для "tor" (сам
relay витримує пропорційно більше onion-трафіку) + м'який sub-limit на
заявлений ідентифікатор (щоб один клієнт не забрав увесь глобальний
пул). Явно НЕ per-pubkey як єдиний захист — це відкрило б targeted DoS
(знаючи чиюсь pubkey, спамити саме під неї через Tor).
"""
from __future__ import annotations

import pytest
from starlette.requests import Request

from morok_relay import rate_limit as rl

pytestmark = pytest.mark.asyncio


def _fake_tor_request(body: dict | None = None, path_params: dict | None = None):
    """Мінімальний ASGI Request із заголовком, що позначає onion-джерело."""
    import json

    body_bytes = json.dumps(body).encode() if body is not None else b""
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/x",
        "headers": [(b"x-morok-via", b"tor")],
        "client": ("10.0.0.1", 1234),  # адреса довіреного проксі (nginx)
        "path_params": path_params or {},
    }

    async def receive():
        return {"type": "http.request", "body": body_bytes, "more_body": False}

    req = Request(scope, receive)
    req._body = body_bytes  # Starlette кешує тіло — заповнюємо напряму
    return req


@pytest.fixture(autouse=True)
def _trust_the_fake_proxy(monkeypatch):
    """get_ip_from_request довіряє forwarded-заголовкам лише від
    trusted_proxy_ips — підставляємо фейковий peer у список довірених."""
    from morok_relay.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "trusted_proxy_ips", "10.0.0.1")


async def test_non_tor_traffic_unaffected(redis, monkeypatch):
    """
    Головна гарантія: для звичайного (не-Tor) трафіку поведінка НЕ
    змінюється взагалі — жодного додаткового виклику Redis, той самий
    ліміт.
    """
    scope = {
        "type": "http", "method": "POST", "path": "/x",
        "headers": [], "client": ("203.0.113.5", 1234), "path_params": {},
    }
    async def receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}
    req = Request(scope, receive)

    calls = []
    real = rl.check_rate_limit
    async def counting(*a, **kw):
        calls.append(a[2])  # identifier
        return await real(*a, **kw)
    monkeypatch.setattr(rl, "check_rate_limit", counting)

    await rl._tor_aware_check(req, redis, "auth_challenge", 10, claimed_identity=None)
    assert calls == ["203.0.113.5"], "non-Tor шлях зробив зайвий/інший виклик"


async def test_tor_global_ceiling_is_raised(redis):
    """
    Глобальна стеля для Tor вища за базовий ліміт у TOR_GLOBAL_MULTIPLIER
    разів — інакше сплеск легітимного onion-трафіку впирався б у той
    самий ліміт, що й одна людина.
    """
    req = _fake_tor_request(body={"pubkey_hex": None})
    base_limit = 5
    hits = 0
    for _ in range(base_limit + 1):
        allowed, _, _ = await rl._tor_aware_check(
            req, redis, "probe_bucket", base_limit, claimed_identity=None,
        )
        if allowed:
            hits += 1
        else:
            break
    assert hits > base_limit, "глобальна стеля не піднята для tor"


async def test_one_claimed_identity_does_not_exhaust_others(redis):
    """
    ГОЛОВНИЙ ТЕСТ. Зловмисник спамить під одним заявленим pubkey через
    Tor — інший, легітимний pubkey (теж через Tor) досі має власний
    ліміт і не блокується.
    """
    limit = 3
    attacker_pk = "aa" * 32
    victim_pk = "bb" * 32

    # Зловмисник вичерпує СВІЙ sub-limit
    for _ in range(limit + 2):
        await rl._tor_aware_check(
            _fake_tor_request(), redis, "auth_verify", limit,
            claimed_identity=attacker_pk,
        )

    # Жертва з ІНШИМ заявленим pubkey — досі проходить
    allowed, _, _ = await rl._tor_aware_check(
        _fake_tor_request(), redis, "auth_verify", limit,
        claimed_identity=victim_pk,
    )
    assert allowed is True, \
        "один Tor-клієнт вичерпав ліміт для ІНШОГО заявленого pubkey"


async def test_claimed_identity_sub_limit_still_applies_within_global_ceiling(redis):
    """Sub-limit реальний: той самий заявлений pubkey після ліміту падає."""
    limit = 3
    pk = "cc" * 32
    results = []
    for _ in range(limit + 3):
        allowed, _, _ = await rl._tor_aware_check(
            _fake_tor_request(), redis, "auth_verify", limit,
            claimed_identity=pk,
        )
        results.append(allowed)
    assert results[:limit] == [True] * limit
    assert False in results[limit:], "sub-limit не спрацював"


async def test_no_claimed_identity_falls_back_to_global_only(redis):
    """Без заявленої ідентичності (malformed body) — тільки глобальна
    стеля, без падіння з помилкою."""
    req = _fake_tor_request(body={"garbage": True})
    allowed, _, _ = await rl._tor_aware_check(
        req, redis, "auth_challenge", 5, claimed_identity=None,
    )
    assert allowed is True


# ── dependency factories: витягування ідентичності ───────────────────────
async def test_body_pubkey_extractor_reads_json(redis):
    dep = rl.rate_limit_tor_aware_by_body_pubkey("auth_challenge", 10)
    req = _fake_tor_request(body={"pubkey_hex": "dd" * 32})
    # dependency сама не кидає — виклик не має підняти виняток при
    # валідному запиті в межах ліміту
    await dep(req, redis)


async def test_body_pubkey_extractor_survives_malformed_json(redis):
    dep = rl.rate_limit_tor_aware_by_body_pubkey("auth_challenge", 10)
    scope = {
        "type": "http", "method": "POST", "path": "/x",
        "headers": [(b"x-morok-via", b"tor")],
        "client": ("10.0.0.1", 1234), "path_params": {},
    }
    async def receive():
        return {"type": "http.request", "body": b"not-json{{{", "more_body": False}
    req = Request(scope, receive)
    req._body = b"not-json{{{"
    await dep(req, redis)  # не має впасти з 500


async def test_path_param_extractor_uses_username(redis):
    dep = rl.rate_limit_tor_aware_by_path_param("backup_restore", 3, "username")
    req = _fake_tor_request(path_params={"username": "alice"})
    await dep(req, redis)


async def test_path_param_extractor_isolates_usernames(redis):
    """Той самий принцип, що для pubkey: різні username через Tor не
    ділять один вичерпаний ліміт."""
    dep = rl.rate_limit_tor_aware_by_path_param("backup_restore", 2, "username")

    import contextlib
    for _ in range(4):
        with contextlib.suppress(Exception):
            # очікувано впаде на ліміті — нас цікавить ІНШЕ ім'я нижче
            await dep(_fake_tor_request(path_params={"username": "spammed"}), redis)

    # інший username — не постраждав
    await dep(_fake_tor_request(path_params={"username": "untouched"}), redis)
