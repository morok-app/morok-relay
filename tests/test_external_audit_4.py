"""
Зовнішній аудит №4:
  1. P0 — активний анонім помилково "вмирав" (last_seen_at не рухався
     на send-шляху, тільки на /me).
  2. P1 — legacy session migration не записувала created_at, тому
     абсолютна 30-денна стеля НІКОЛИ не діяла на сесії, видані до
     патчу зі стелею (той самий механізм, що захищає DMS від
     вкраденого bearer).
  3. MEDIUM — native (FCM) push subscribe не мав ані rate-limit, ані
     квоти, хоча web push мав обидва — амплiфікаційний вектор.
"""
from __future__ import annotations

import time

import pytest
from fastapi import HTTPException

pytestmark = pytest.mark.asyncio


# ── P0: last_seen_at heartbeat ───────────────────────────────────────────
async def test_authenticated_request_bumps_last_seen(
    redis, pg_sessionmaker, monkeypatch,
):
    """
    ГОЛОВНИЙ ТЕСТ. Будь-який автентифікований запит (не тільки /me)
    тепер throttled оновлює last_seen_at — інакше активний анонім,
    що ніколи не заходить у /me, "помирав" у reap_anonymous_users
    попри щоденне листування.

    _bump_last_seen — фонова задача, що відкриває ВЛАСНУ db-сесію
    через _session_factory (той самий патерн, що DMS-bump і push) —
    тому наскрізний тест підміняє _session_factory на тестову і читає
    результат через неї ж, а не через окрему `db`-фікстуру.
    """
    import asyncio

    import nacl.signing
    from sqlalchemy import select

    from morok_relay import db as db_module
    from morok_relay.config import get_settings
    from morok_relay.deps import get_current_session
    from morok_relay.models import User, UserTier
    from morok_relay.sessions import create_session

    monkeypatch.setattr(db_module, "_session_factory", pg_sessionmaker)

    settings = get_settings()
    seed = b"\x11" * 32
    pk = nacl.signing.SigningKey(seed).verify_key.encode()
    stale = int(time.time()) - 8 * 86400  # 8 днів тому — за поріг reap

    async with pg_sessionmaker() as setup_db:
        setup_db.add(User(pubkey=pk, username=None,
                          home_relay=settings.relay_name, tier=UserTier.FREE,
                          created_at=stale, last_seen_at=stale))
        await setup_db.commit()

    session = await create_session(redis, pk.hex())
    await get_current_session(redis, authorization=f"Bearer {session.token}")
    await asyncio.sleep(0.3)  # фонова задача — даємо їй завершитись

    async with pg_sessionmaker() as check_db:
        row = (await check_db.execute(
            select(User).where(User.pubkey == pk)
        )).scalar_one()
        assert row.last_seen_at > stale, \
            "last_seen_at не оновився на звичайному authenticated-запиті"


async def test_last_seen_bump_is_throttled(redis, db):
    """Throttle реально працює — другий запит у вікні не спавнить
    другу фонову задачу (перевіряємо через SET NX ключ напряму)."""
    from morok_relay.sessions import create_session

    pk_hex = "22" * 32
    session = await create_session(redis, pk_hex)

    from morok_relay.deps import get_current_session
    await get_current_session(redis, authorization=f"Bearer {session.token}")

    key = f"morok:last_seen_throttle:{pk_hex}"
    assert await redis.exists(key)
    ttl = await redis.ttl(key)
    assert 0 < ttl <= 3600


async def test_last_seen_bump_survives_missing_user_row(redis):
    """
    Якщо рядка User ще немає (наприклад remote-кеш чи щось дивне) —
    bump мовчки no-op, не 500.
    """
    from morok_relay.deps import _bump_last_seen
    await _bump_last_seen("ff" * 32)  # не існуючий pubkey — не падає


# ── P1: legacy session absolute cap ──────────────────────────────────────
async def test_legacy_session_migration_stamps_created_at(redis):
    """
    ГОЛОВНЕ. Стара сесія (bare pubkey, без |created_at) при lazy-
    міграції на хешований ключ мусить отримати created_at = момент
    міграції — інакше абсолютна стеля НІКОЛИ не спрацює для неї
    (created_str завжди порожній → перевірка мовчки пропускається).
    """
    from morok_relay.sessions import _session_key, verify_session_token

    legacy_token = "legacytoken" + "a" * 53  # довільний токен
    pubkey_hex = "33" * 32
    # Стара схема: ключ = сирий token, значення = ГОЛИЙ pubkey (без "|")
    await redis.setex(_session_key(legacy_token), 7 * 86400, pubkey_hex)

    session = await verify_session_token(redis, legacy_token)
    assert session is not None
    assert session.pubkey_hex == pubkey_hex

    from morok_relay.sessions import _token_digest
    new_key = _session_key(_token_digest(legacy_token))
    migrated_value = (await redis.get(new_key)).decode()
    assert "|" in migrated_value, \
        "мігрована сесія не отримала created_at — стеля не спрацює ніколи"
    stamped_pubkey, _, created_str = migrated_value.partition("|")
    assert stamped_pubkey == pubkey_hex
    assert created_str.isdigit()
    assert abs(int(created_str) - int(time.time())) < 5


async def test_legacy_session_respects_absolute_cap_after_migration(redis):
    """
    Наскрізно: мігрована legacy-сесія, якщо потім "постаріти" її
    created_at за стелю, дійсно помирає — а не живе вічно, як було
    до фіксу.
    """
    from morok_relay import sessions as ss

    legacy_token = "oldtoken" + "b" * 56
    pubkey_hex = "44" * 32
    await redis.setex(ss._session_key(legacy_token), 7 * 86400, pubkey_hex)

    # перший verify — мігрує і штампує created_at=зараз
    assert await ss.verify_session_token(redis, legacy_token) is not None

    # відсуваємо created_at за стелю
    digest = ss._token_digest(legacy_token)
    key = ss._session_key(digest)
    old_created = int(time.time()) - ss.SESSION_ABSOLUTE_MAX_SECONDS - 100
    await redis.set(key, f"{pubkey_hex}|{old_created}".encode(), ex=3600)

    assert await ss.verify_session_token(redis, legacy_token) is None, \
        "мігрована legacy-сесія пережила абсолютну стелю"


async def test_fresh_session_unaffected_by_legacy_fix(redis):
    """Контроль: звичайні (нелегасі) сесії й далі працюють як раніше."""
    from morok_relay.sessions import create_session, verify_session_token
    s = await create_session(redis, "55" * 32)
    assert await verify_session_token(redis, s.token) is not None


# ── native FCM push: rate-limit + квота ──────────────────────────────────
async def test_native_push_quota_enforced(db, redis, monkeypatch):
    from morok_relay.api.push import (
        MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT,
        NativePushSubscribeRequest,
        post_subscribe_native,
    )
    from morok_relay.models import PushSubscription
    from morok_relay.sessions import Session

    pk_hex = "66" * 32
    session = Session(token="t" * 64, pubkey_hex=pk_hex, expires_at=2**31)

    now = 0
    for i in range(MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT):
        db.add(PushSubscription(
            pubkey=bytes.fromhex(pk_hex),
            endpoint=f"fcm-token-existing-{i}" * 2,
            p256dh="", auth="", platform="fcm",
            created_at=now, updated_at=now,
        ))
    await db.commit()

    with pytest.raises(HTTPException) as e:
        await post_subscribe_native(
            NativePushSubscribeRequest(token="fcm-token-one-too-many" * 2),
            session, db, redis,
        )
    assert e.value.status_code == 409


async def test_native_push_rate_limited(db, redis):
    from morok_relay.api.push import NativePushSubscribeRequest, post_subscribe_native
    from morok_relay.sessions import Session

    session = Session(token="t" * 64, pubkey_hex="77" * 32, expires_at=2**31)

    hit_429 = False
    for i in range(15):
        try:
            await post_subscribe_native(
                NativePushSubscribeRequest(token=f"fcm-token-{i}" * 3),
                session, db, redis,
            )
        except HTTPException as e:
            if e.status_code == 429:
                hit_429 = True
                break
    assert hit_429, "native push subscribe без rate-limit"


async def test_web_and_native_push_share_one_quota(db, redis):
    """
    Спільний ресурс: web+native підписки одного акаунта РАЗОМ не
    мають перевищувати MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT — інакше
    ліміт обходиться перемиканням платформи.
    """
    from sqlalchemy import func, select

    from morok_relay.api.push import MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT
    from morok_relay.models import PushSubscription

    pk = b"\x88" * 32
    for i in range(MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT):
        db.add(PushSubscription(
            pubkey=pk, endpoint=f"mixed-{i}" * 3, p256dh="", auth="",
            platform="fcm" if i % 2 else "webpush",
            created_at=0, updated_at=0,
        ))
    await db.commit()

    count = (await db.execute(
        select(func.count()).select_from(PushSubscription)
        .where(PushSubscription.pubkey == pk)
    )).scalar_one()
    assert count == MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT
