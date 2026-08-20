"""
Ticket-based WS auth (аудит зовн. №5, доповнення до critical WS-token-
leak фіксу). Паралельний, зворотно-сумісний шлях: клієнт отримує
короткоживучий одноразовий ticket через звичайний HTTP bearer (POST
/auth/ws-ticket), підключається WS з ?ticket= замість ?token=. Старий
?token= шлях лишається БЕЗ ЗМІН.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio

OWNER = "aa" * 32


# ── issue_ws_ticket / consume_ws_ticket: чиста логіка ────────────────────
async def test_ticket_resolves_to_correct_pubkey(redis):
    from morok_relay.sessions import consume_ws_ticket, issue_ws_ticket
    ticket = await issue_ws_ticket(redis, OWNER)
    resolved = await consume_ws_ticket(redis, ticket)
    assert resolved == OWNER


async def test_ticket_is_one_time_use(redis):
    """ГОЛОВНИЙ ТЕСТ. Ticket одноразовий — друге споживання того
    самого значення повертає None."""
    from morok_relay.sessions import consume_ws_ticket, issue_ws_ticket
    ticket = await issue_ws_ticket(redis, OWNER)
    assert await consume_ws_ticket(redis, ticket) == OWNER
    assert await consume_ws_ticket(redis, ticket) is None


async def test_unknown_ticket_returns_none(redis):
    from morok_relay.sessions import consume_ws_ticket
    assert await consume_ws_ticket(redis, "nonexistent-ticket-xyz") is None


async def test_ticket_has_short_ttl(redis):
    from morok_relay.sessions import WS_TICKET_TTL_SECONDS, issue_ws_ticket
    ticket = await issue_ws_ticket(redis, OWNER)
    ttl = await redis.ttl(f"morok:ws_ticket:{ticket}")
    assert 0 < ttl <= WS_TICKET_TTL_SECONDS


async def test_different_users_get_different_tickets(redis):
    from morok_relay.sessions import consume_ws_ticket, issue_ws_ticket
    t1 = await issue_ws_ticket(redis, "11" * 32)
    t2 = await issue_ws_ticket(redis, "22" * 32)
    assert t1 != t2
    assert await consume_ws_ticket(redis, t1) == "11" * 32
    assert await consume_ws_ticket(redis, t2) == "22" * 32


# ── POST /auth/ws-ticket: наскрізно ──────────────────────────────────────
async def test_ws_ticket_endpoint_issues_valid_ticket(redis):
    from morok_relay.api.auth import get_ws_ticket
    from morok_relay.sessions import Session, consume_ws_ticket

    session = Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)
    result = await get_ws_ticket(session, redis)

    assert "ticket" in result
    assert result["expires_in"] > 0

    resolved = await consume_ws_ticket(redis, result["ticket"])
    assert resolved == OWNER


# ── has_any_live_session: для ticket-based pinger-перевірки ──────────────
async def test_has_any_live_session_true_when_session_exists(redis):
    from morok_relay.sessions import create_session, has_any_live_session
    await create_session(redis, "33" * 32)
    assert await has_any_live_session(redis, "33" * 32) is True


async def test_has_any_live_session_false_for_unknown_user(redis):
    from morok_relay.sessions import has_any_live_session
    assert await has_any_live_session(redis, "44" * 32) is False


async def test_has_any_live_session_false_after_revoke_all(redis):
    from morok_relay.sessions import (
        create_session,
        has_any_live_session,
        revoke_all_sessions,
    )
    pk = "55" * 32
    await create_session(redis, pk)
    await create_session(redis, pk)  # два "пристрої"
    assert await has_any_live_session(redis, pk) is True

    await revoke_all_sessions(redis, pk)
    assert await has_any_live_session(redis, pk) is False


async def test_has_any_live_session_true_if_one_of_several_remains(redis):
    """Один з кількох живих токенів — все ще True."""
    from morok_relay.sessions import (
        create_session,
        has_any_live_session,
        revoke_session,
    )
    pk = "66" * 32
    s1 = await create_session(redis, pk)
    await create_session(redis, pk)
    await revoke_session(redis, s1.token)
    assert await has_any_live_session(redis, pk) is True


# ── redaction filter вже покриває ?ticket= (перевірено вчора, контроль) ──
async def test_redaction_already_covers_ticket_param():
    """
    Контроль консистентності: redaction-фільтр з учорашнього critical-
    фіксу вже explicitly обробляв ?ticket= ЗАЗДАЛЕГІДЬ, до появи самого
    ticket-механізму. Переконуємось, що це досі так — інакше цей
    новий фіче зробив би токен теоретично видимим тим самим шляхом,
    який ми щойно закрили для ?token=.
    """
    import io
    import logging

    import morok_relay.main  # noqa

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    uv_logger = logging.getLogger("uvicorn.error")
    uv_logger.addHandler(handler)
    uv_logger.setLevel(logging.INFO)
    try:
        uv_logger.info(
            'WebSocket /ws/v1/inbox?ticket=%s [accepted]',
            "realtickettoken1234567890abcdef",
        )
        output = stream.getvalue()
    finally:
        uv_logger.removeHandler(handler)
    assert "realtickettoken1234567890abcdef" not in output


# ── legacy token-шлях лишається БЕЗ ЗМІН ──────────────────────────────────
async def test_legacy_token_path_still_works_unchanged(redis):
    """Контроль зворотної сумісності: старий ?token= шлях (verify_
    session_token) не зачеплений появою ticket-механізму."""
    from morok_relay.sessions import create_session, verify_session_token
    s = await create_session(redis, "77" * 32)
    session = await verify_session_token(redis, s.token)
    assert session is not None
    assert session.pubkey_hex == "77" * 32
