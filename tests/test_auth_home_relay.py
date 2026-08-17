"""
home_relay у відповіді auth (зловлено в проді 17.08).

Сесію auth видає БУДЬ-ЯКИЙ релей — задумано. Але користувач, що
залогінився не на свій дім, бачить порожній inbox: повідомлення
федеруються на home_relay і чекають там (реальний випадок: honduras
з домом relay1 сидів клієнтом на relay2 і «не отримував» повідомлень,
які спокійно лежали на relay1). Сервер тепер віддає home_relay +
is_home_relay, клієнт попереджає. Поля адитивні — старі клієнти
ігнорують.
"""
from __future__ import annotations

import time
import typing

import pytest
from sqlalchemy import delete

from morok_relay.api.auth import verify_challenge
from morok_relay.config import get_settings
from morok_relay.crypto import canonical_json, ed25519_sign
from morok_relay.models import LoginLog, User, UserTier
from morok_relay.schemas import AuthRequest
from morok_relay.sessions import store_challenge

pytestmark = pytest.mark.asyncio


class _Req:
    headers: typing.ClassVar[dict] = {}

    class client:
        host = "127.0.0.1"


async def _do_auth(redis, db, seed: bytes):
    import nacl.signing
    sk = nacl.signing.SigningKey(seed)
    pubkey_hex = sk.verify_key.encode().hex()
    challenge = "ab" * 32
    await store_challenge(redis, challenge, pubkey_hex)
    ts = int(time.time())
    msg = canonical_json({
        "morok_auth": "v1", "challenge": challenge,
        "pubkey": pubkey_hex, "timestamp": ts,
    })
    sig = ed25519_sign(msg, bytes(sk._seed))  # 32-байтний priv seed
    body = AuthRequest(
        pubkey_hex=pubkey_hex, challenge_hex=challenge,
        timestamp=ts, signature_hex=sig.hex(),
    )
    resp = await verify_challenge(body, redis, db, _Req())
    return pubkey_hex, resp


async def test_first_login_is_home(redis, db):
    """Перший вхід узагалі: рядка ще немає → is_home=True, home=None."""
    _, resp = await _do_auth(redis, db, b"\x11" * 32)
    assert resp.is_home_relay is True
    assert resp.home_relay is None
    await db.rollback()


async def test_local_user_is_home(redis, db):
    settings = get_settings()
    import nacl.signing
    seed = b"\x22" * 32
    pk = nacl.signing.SigningKey(seed).verify_key.encode()
    db.add(User(pubkey=pk, home_relay=settings.relay_name,
                tier=UserTier.FREE, last_seen_at=int(time.time())))
    await db.commit()

    _, resp = await _do_auth(redis, db, seed)
    assert resp.is_home_relay is True
    assert resp.home_relay == settings.relay_name
    await db.execute(delete(LoginLog))
    await db.commit()


async def test_foreign_home_flagged_and_row_untouched(redis, db):
    """
    ГОЛОВНЕ: логін чужого (дім — інший релей) → is_home=False,
    home_relay чесно вказаний, і auth НЕ переписує рядок під себе.
    """
    import nacl.signing
    seed = b"\x33" * 32
    pk = nacl.signing.SigningKey(seed).verify_key.encode()
    db.add(User(pubkey=pk, username="wanderer",
                home_relay="relay-other.example.com",
                tier=UserTier.FREE, last_seen_at=int(time.time())))
    await db.commit()

    _, resp = await _do_auth(redis, db, seed)
    assert resp.is_home_relay is False
    assert resp.home_relay == "relay-other.example.com"

    from sqlalchemy import select
    row = (await db.execute(select(User).where(User.pubkey == pk))).scalar_one()
    assert row.home_relay == "relay-other.example.com", \
        "auth «всиновив» чужого користувача"
    await db.execute(delete(LoginLog))
    await db.commit()


async def test_session_still_issued_on_foreign_relay(redis, db):
    """Сесія на нерідному релеї ВИДАЄТЬСЯ — це фіча (відновлення), не бан."""
    import nacl.signing
    seed = b"\x44" * 32
    pk = nacl.signing.SigningKey(seed).verify_key.encode()
    db.add(User(pubkey=pk, home_relay="relay-other.example.com",
                tier=UserTier.FREE, last_seen_at=int(time.time())))
    await db.commit()

    _, resp = await _do_auth(redis, db, seed)
    assert resp.session_token and len(resp.session_token) == 64
    await db.execute(delete(LoginLog))
    await db.commit()


# ── /me несе is_home_relay (для збережених сесій) ────────────────────────
async def test_me_reports_foreign_home(redis, db):
    """
    Auth клієнт може не проходити до 30 днів (збережена сесія) — тож
    «ти не вдома» мусить бути видно і в /me, який смикається при
    кожному відкритті. Саме цей кейс зловили наживо: повторний вхід
    honduras'а на relay2 НЕ дав non-home рядка в лозі, бо auth не
    відбувався — сесія відновилась із localStorage.
    """
    from morok_relay.api.users import get_me
    from morok_relay.sessions import Session

    pk = b"\x55" * 32
    db.add(User(pubkey=pk, username="roamer",
                home_relay="relay-other.example.com",
                tier=UserTier.FREE, last_seen_at=int(time.time()),
                created_at=int(time.time())))
    await db.commit()

    session = Session(token="t" * 64, pubkey_hex=pk.hex(), expires_at=2**31)
    me = await get_me(session, db)
    assert me.is_home_relay is False
    assert me.home_relay == "relay-other.example.com"
    await db.commit()


async def test_me_home_user_true(redis, db):
    from morok_relay.api.users import get_me
    from morok_relay.sessions import Session

    settings = get_settings()
    pk = b"\x66" * 32
    db.add(User(pubkey=pk, home_relay=settings.relay_name,
                tier=UserTier.FREE, last_seen_at=int(time.time()),
                created_at=int(time.time())))
    await db.commit()

    me = await get_me(Session(token="t" * 64, pubkey_hex=pk.hex(),
                              expires_at=2**31), db)
    assert me.is_home_relay is True
    await db.commit()
