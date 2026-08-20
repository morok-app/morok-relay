"""
DMS quota — справжня атомарність під concurrency (аудит зовн. №5,
MEDIUM).

Знахідка: коментар у create_dms стверджував, що гонка "в найгіршому
разі дає ОДИН зайвий рядок" — неправда. N одночасних create_dms могли
всі виконати SELECT COUNT до того, як хоч один закомітить INSERT,
побачити однаковий active_count і всі пройти. Той самий клас, що вже
закривали в inbox depth (Lua EVAL) і group capacity (SELECT FOR
UPDATE) — тут фікс через pg_advisory_xact_lock(hashtext(pubkey)), той
самий підхід, що вже стоїть для mail-квоти в api/mail.py.

Тест — СПРАВЖНІЙ паралелізм (asyncio.Barrier + окремі сесії з
pg_sessionmaker + явний commit, як робить продакшн DBSession
dependency), не просто послідовні виклики: без цих деталей тест
хибно "проходив би" незалежно від того, чи фікс на місці — той самий
урок, що вже був із group capacity race.
"""
from __future__ import annotations

import asyncio
import base64
import time

import pytest
from fastapi import HTTPException

from morok_relay.schemas import DMS_FREE_TIER_MAX_ACTIVE, DMSCreate

pytestmark = pytest.mark.asyncio

OWNER = "aa" * 32


def _create_body(size_bytes: int = 100) -> DMSCreate:
    return DMSCreate(
        trigger_seconds=86400,
        payload_encrypted=base64.b64encode(b"\x01" * size_bytes).decode(),
        recipient_pubkeys_hex=["bb" * 32],
        label=None,
    )


async def test_concurrent_create_dms_never_exceeds_active_quota(
    pg_sessionmaker, monkeypatch,
):
    """
    ГОЛОВНИЙ ТЕСТ. Квота вже майже вичерпана (max_active - 1 активних
    DMS існує). Десять паралельних create_dms на ОСТАННЄ вільне
    місце — атомарно (advisory lock) має пройти рівно один.
    """
    from morok_relay import db as db_module
    from morok_relay.api.dms import create_dms
    from morok_relay.config import get_settings
    from morok_relay.models import DeadManSwitch, DMSStatus, User, UserTier
    from morok_relay.sessions import Session

    monkeypatch.setattr(db_module, "_session_factory", pg_sessionmaker)

    settings = get_settings()
    now = int(time.time())

    async with pg_sessionmaker() as setup_db:
        setup_db.add(User(
            pubkey=bytes.fromhex(OWNER), tier=UserTier.FREE,
            home_relay=settings.relay_name,
            created_at=now, last_seen_at=now,
        ))
        # DMS_FREE_TIER_MAX_ACTIVE - 1 активних DMS — рівно ОДНЕ вільне
        # місце лишається під квотою.
        for _i in range(DMS_FREE_TIER_MAX_ACTIVE - 1):
            setup_db.add(DeadManSwitch(
                creator_pubkey=bytes.fromhex(OWNER),
                trigger_seconds=86400, last_check_in_at=now,
                payload_encrypted=b"\x01" * 50, status=DMSStatus.ARMED,
                created_at=now,
            ))
        await setup_db.commit()

    session = Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)

    # Barrier синхронізує паралельні задачі ПІСЛЯ _get_current_user
    # (перший await у create_dms) — без цього швидкий локальний
    # Postgres міг би виконати запити настільки послідовно, що вони
    # просто не перетнуться в критичній секції, і тест хибно "пройшов
    # би" навіть без фіксу (той самий урок, що вже був із group
    # capacity race).
    import morok_relay.api.dms as dms_mod
    real_get_user = dms_mod._get_current_user
    barrier = asyncio.Barrier(10)

    async def synced_get_user(db_, pubkey_hex):
        result = await real_get_user(db_, pubkey_hex)
        await barrier.wait()
        return result

    async def try_create() -> bool:
        async with pg_sessionmaker() as own_db:
            try:
                await create_dms(_create_body(), session, own_db)
                await own_db.commit()
                return True
            except HTTPException:
                await own_db.rollback()
                return False

    dms_mod._get_current_user = synced_get_user
    try:
        results = await asyncio.gather(*[try_create() for _ in range(10)])
    finally:
        dms_mod._get_current_user = real_get_user

    accepted = sum(results)
    assert accepted == 1, \
        f"прийнято {accepted} нових DMS замість рівно 1 — quota race"

    from sqlalchemy import func, select
    async with pg_sessionmaker() as check_db:
        count = (await check_db.execute(
            select(func.count()).select_from(DeadManSwitch)
            .where(
                DeadManSwitch.creator_pubkey == bytes.fromhex(OWNER),
                DeadManSwitch.status == DMSStatus.ARMED,
            )
        )).scalar_one()
    assert count == DMS_FREE_TIER_MAX_ACTIVE, \
        f"фактична кількість активних DMS {count} != квоти {DMS_FREE_TIER_MAX_ACTIVE}"


async def test_create_dms_still_works_normally(db):
    """Контроль: звичайний одиночний create_dms не зламаний advisory lock."""
    from morok_relay.api.dms import create_dms
    from morok_relay.config import get_settings
    from morok_relay.models import User, UserTier
    from morok_relay.sessions import Session

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex("cc" * 32), tier=UserTier.FREE,
                home_relay=settings.relay_name,
                created_at=now, last_seen_at=now))
    await db.commit()

    session = Session(token="t" * 64, pubkey_hex="cc" * 32, expires_at=2**31)
    info = await create_dms(_create_body(), session, db)
    assert info.dms_id
