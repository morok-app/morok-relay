"""
DELETE /me: retry + чесний sessions_revoked (аудит зовн. №5, MEDIUM).

Знахідка: якщо revoke_all_sessions падав ПІСЛЯ стирання SQL-даних,
сервер логував WARNING і однаково відповідав {"deleted": true} —
мовчазна брехня: акаунт стерто, а старі bearer могли лишитись
живими. Правдива атомарність тут неможлива (Postgres і Redis —
окремі системи), тож чесний компроміс: кілька спроб проти тимчасового
блимка + явний прапорець у відповіді замість мовчання.
"""
from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.asyncio


async def _make_user(db, pubkey_hex: str, username: str):
    from morok_relay.config import get_settings
    from morok_relay.models import User, UserTier

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(pubkey_hex), username=username,
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()


async def test_delete_me_reports_sessions_revoked_true_on_success(db, redis):
    """Контроль: звичайний успішний шлях — прапорець True, як і мало
    бути завжди (просто тепер це явний контракт, не implicit)."""
    from morok_relay.api.account import delete_me
    from morok_relay.sessions import Session, create_session

    pk = "11" * 32
    await _make_user(db, pk, "alice")
    await create_session(redis, pk)  # реальна жива сесія в Redis

    session = Session(token="t" * 64, pubkey_hex=pk, expires_at=2**31)
    result = await delete_me(session, db, redis, proof=None)
    assert result == {"deleted": True, "sessions_revoked": True}


async def test_delete_me_reports_false_when_redis_permanently_down(
    db, redis, monkeypatch,
):
    """
    ГОЛОВНИЙ ТЕСТ. Redis-revoke падає на КОЖНІЙ з трьох спроб — сервер
    мусить чесно повернути sessions_revoked=False, а НЕ мовчки
    "deleted: true" без жодного сигналу. Account-видалення (SQL-
    частина) при цьому все одно завершується — ми не хочемо
    заблокувати людину від видалення акаунта через проблему з Redis.
    """
    from morok_relay.api.account import delete_me
    from morok_relay.sessions import Session

    pk = "22" * 32
    await _make_user(db, pk, "bob")

    import morok_relay.api.account as account_mod

    async def always_fails(*a, **kw):
        raise ConnectionError("redis permanently down")

    monkeypatch.setattr(account_mod, "revoke_all_sessions", always_fails)

    session = Session(token="t" * 64, pubkey_hex=pk, expires_at=2**31)
    result = await delete_me(session, db, redis, proof=None)

    assert result["deleted"] is True, \
        "видалення акаунта не повинно блокуватись через Redis-збій"
    assert result["sessions_revoked"] is False, \
        "збій Redis мовчки прихований — контракт відповіді бреше"


async def test_delete_me_retries_before_giving_up(db, redis, monkeypatch):
    """
    Тимчасовий блимок (перші дві спроби падають, третя — успішна) не
    повинен призводити до sessions_revoked=False: retry має витягнути
    легітимний тимчасовий збій.
    """
    from morok_relay.api.account import delete_me
    from morok_relay.sessions import Session

    pk = "33" * 32
    await _make_user(db, pk, "carol")

    import morok_relay.api.account as account_mod
    real_revoke = account_mod.revoke_all_sessions
    attempts = {"n": 0}

    async def flaky(*a, **kw):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise ConnectionError("transient blip")
        return await real_revoke(*a, **kw)

    monkeypatch.setattr(account_mod, "revoke_all_sessions", flaky)

    session = Session(token="t" * 64, pubkey_hex=pk, expires_at=2**31)
    result = await delete_me(session, db, redis, proof=None)

    assert attempts["n"] == 3, "retry не витримав рівно 3 спроби"
    assert result["sessions_revoked"] is True, \
        "тимчасовий блимок мав бути витягнутий retry-механізмом"


async def test_delete_me_account_data_wiped_even_when_redis_fails(
    db, redis, monkeypatch,
):
    """
    Незалежна перевірка: SQL-стирання (username звільнено, deleted_at
    проставлено) відбувається НЕЗАЛЕЖНО від того, чи вдався Redis-
    revoke — людина не має бути заблокована від видалення акаунта
    через проблему з іншим сервісом.
    """
    from morok_relay.api.account import delete_me
    from morok_relay.sessions import Session

    pk = "44" * 32
    await _make_user(db, pk, "dave")

    import morok_relay.api.account as account_mod

    async def always_fails(*a, **kw):
        raise ConnectionError("redis down")

    monkeypatch.setattr(account_mod, "revoke_all_sessions", always_fails)

    session = Session(token="t" * 64, pubkey_hex=pk, expires_at=2**31)
    await delete_me(session, db, redis, proof=None)

    from sqlalchemy import select

    from morok_relay.models import User
    row = (await db.execute(
        select(User).where(User.pubkey == bytes.fromhex(pk))
    )).scalar_one()
    assert row.deleted_at is not None
    assert row.username is None
