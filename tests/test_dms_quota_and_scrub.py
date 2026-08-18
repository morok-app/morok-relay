"""
Dead Man's Switch: квота + scrub ciphertext (аудит зовн. №3, HIGH —
"машина для забивання Postgres").

Знахідка: create_dms обмежувала лише ЧАСТОТУ (5/хв через rate-limit),
а не накопичений стан. При 256 KB на запис — до ~1.76 GiB/добу з
ОДНОГО pubkey; Ed25519-ідентичності дешеві, per-pubkey rate-limit не є
Sybil-перешкодою. Додатково: cancel лише ставив статус, ciphertext
лишався в БД навіть після того, як власник explicitly його відкликав;
той самий payload лишався і після успішного тригера, хоча вже був
доставлений одержувачам як звичайний конверт. Termінальні рядки
взагалі не мали cleanup'у.
"""
from __future__ import annotations

import base64
import time
import uuid

import pytest
from fastapi import HTTPException

from morok_relay.api.dms import cancel_dms, create_dms
from morok_relay.models import DeadManSwitch, DMSStatus, User, UserTier
from morok_relay.schemas import (
    DMS_FREE_TIER_MAX_ACTIVE,
    DMSCreate,
)
from morok_relay.sessions import Session

pytestmark = pytest.mark.asyncio

OWNER = "77" * 32


def _session() -> Session:
    return Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)


async def _ensure_user(db, pubkey_hex: str) -> None:
    from sqlalchemy import select

    from morok_relay.config import get_settings
    pk = bytes.fromhex(pubkey_hex)
    existing = (await db.execute(
        select(User).where(User.pubkey == pk)
    )).scalar_one_or_none()
    if existing is None:
        db.add(User(pubkey=pk, tier=UserTier.FREE,
                    home_relay=get_settings().relay_name,
                    created_at=int(time.time()),
                    last_seen_at=int(time.time())))
        await db.commit()


def _create_body(size_bytes: int = 100) -> DMSCreate:
    return DMSCreate(
        trigger_seconds=86400,
        payload_encrypted=base64.b64encode(b"\x01" * size_bytes).decode(),
        recipient_pubkeys_hex=["aa" * 32],
        label=None,
    )


# ── квота: кількість активних ────────────────────────────────────────────
async def test_active_dms_count_capped(db):
    await _ensure_user(db, OWNER)
    for _ in range(DMS_FREE_TIER_MAX_ACTIVE):
        await create_dms(_create_body(), _session(), db)

    with pytest.raises(HTTPException) as e:
        await create_dms(_create_body(), _session(), db)
    assert e.value.status_code == 403
    assert "too_many_active_dms" in e.value.detail


async def test_cancelled_dms_do_not_count_toward_active_quota(db):
    """CANCELLED звільняє місце в квоті — це не "5 DMS назавжди"."""
    await _ensure_user(db, OWNER)
    created_ids = []
    for _ in range(DMS_FREE_TIER_MAX_ACTIVE):
        info = await create_dms(_create_body(), _session(), db)
        created_ids.append(info.dms_id)

    await cancel_dms(created_ids[0], _session(), db)

    # тепер має пройти — один слот звільнився
    info = await create_dms(_create_body(), _session(), db)
    assert info.dms_id


# ── квота: сумарний обсяг байтів ─────────────────────────────────────────
async def test_total_bytes_quota_enforced(db, monkeypatch):
    """
    Байтова квота (2 MiB) значно більша за одну схема-стелю payload'а
    (256 KB), тож щоб перевірити ЛІМІТ, а не схему, тимчасово знижуємо
    квоту до значення, досяжного кількома звичайними DMS.
    """
    import morok_relay.api.dms as dms_mod
    monkeypatch.setattr(dms_mod, "DMS_FREE_TIER_MAX_TOTAL_BYTES", 500)

    await _ensure_user(db, OWNER)
    await create_dms(_create_body(300), _session(), db)
    with pytest.raises(HTTPException) as e:
        await create_dms(_create_body(300), _session(), db)
    assert e.value.status_code == 403
    assert "dms_storage_quota_exceeded" in e.value.detail


async def test_small_payloads_within_quota_allowed(db):
    await _ensure_user(db, OWNER)
    # 3 маленькі DMS — далеко в межах і count-, і byte-квоти
    for _ in range(3):
        info = await create_dms(_create_body(50), _session(), db)
        assert info.dms_id


# ── scrub на cancel ──────────────────────────────────────────────────────
async def test_cancel_scrubs_payload(db):
    """
    ГОЛОВНИЙ ТЕСТ. Власник явно відкликав DMS — ciphertext не має
    лишатись у БД, попри те що рядок (метадані) ще живий якийсь час.
    """
    await _ensure_user(db, OWNER)
    info = await create_dms(_create_body(1000), _session(), db)

    await cancel_dms(info.dms_id, _session(), db)

    row = await db.get(DeadManSwitch, uuid.UUID(info.dms_id))
    assert row.status == DMSStatus.CANCELLED
    assert row.payload_encrypted == b"", \
        "payload лишився в БД після явного cancel"


async def test_double_cancel_is_idempotent_and_stays_scrubbed(db):
    await _ensure_user(db, OWNER)
    info = await create_dms(_create_body(100), _session(), db)
    await cancel_dms(info.dms_id, _session(), db)
    result = await cancel_dms(info.dms_id, _session(), db)
    assert result.cancelled is True

    row = await db.get(DeadManSwitch, uuid.UUID(info.dms_id))
    assert row.payload_encrypted == b""


# ── scrub на trigger (dms_reaper) ────────────────────────────────────────
async def test_reaper_scrubs_payload_only_after_full_delivery(
    pg_sessionmaker, monkeypatch,
):
    """
    payload зануляється ЛИШЕ коли all_delivered — недоставленим
    одержувачам він досі потрібен для наступної спроби reaper'а.

    fire_dms_switches() сама відкриває _session_factory/_redis, тож
    наскрізний тест підмінює саме _session_factory (щоб писати в ту ж
    тестову БД) і мокає доставку одержувачам успішною.
    """
    from morok_relay import db as db_module
    from morok_relay.scripts import dms_reaper

    monkeypatch.setattr(db_module, "_session_factory", pg_sessionmaker)

    now = int(time.time())
    dms_id = uuid.uuid4()
    async with pg_sessionmaker() as setup_db:
        setup_db.add(DeadManSwitch(
            id=dms_id, creator_pubkey=bytes.fromhex(OWNER),
            trigger_seconds=3600,
            last_check_in_at=now - 90000,  # давно протух
            payload_encrypted=b"\x01" * 500,
            status=DMSStatus.ARMED, created_at=now - 90000,
        ))
        await setup_db.commit()

    async def fake_deliver(*a, **kw):
        return True  # доставка одержувачу успішна

    monkeypatch.setattr(dms_reaper, "_build_and_deliver_envelope", fake_deliver)

    stats = await dms_reaper.fire_dms_switches()
    assert stats["errors"] == 0, f"reaper errored: {stats}"

    async with pg_sessionmaker() as check_db:
        row = await check_db.get(DeadManSwitch, dms_id)
        assert row.status == DMSStatus.TRIGGERED
        assert row.payload_encrypted == b"", \
            "payload лишився в БД після повної доставки при тригері"


# ── cleanup terminal DMS ─────────────────────────────────────────────────
async def test_cleanup_removes_old_terminal_dms(db):
    from morok_relay.cleanup import DMS_TERMINAL_RETENTION_SECONDS, reap_terminal_dms

    now = int(time.time())
    old_cancelled = DeadManSwitch(
        id=uuid.uuid4(), creator_pubkey=b"\x01" * 32,
        trigger_seconds=3600, last_check_in_at=now,
        payload_encrypted=b"", status=DMSStatus.CANCELLED,
        created_at=now - DMS_TERMINAL_RETENTION_SECONDS - 100,
        cancelled_at=now - DMS_TERMINAL_RETENTION_SECONDS - 100,
    )
    fresh_triggered = DeadManSwitch(
        id=uuid.uuid4(), creator_pubkey=b"\x02" * 32,
        trigger_seconds=3600, last_check_in_at=now,
        payload_encrypted=b"", status=DMSStatus.TRIGGERED,
        created_at=now - 100, triggered_at=now - 100,
    )
    db.add(old_cancelled)
    db.add(fresh_triggered)
    await db.commit()

    removed = await reap_terminal_dms(db)
    await db.commit()
    assert removed == 1

    from sqlalchemy import select
    left = (await db.execute(select(DeadManSwitch))).scalars().all()
    assert len(left) == 1 and left[0].id == fresh_triggered.id


async def test_cleanup_never_touches_armed_dms(db):
    """ARMED — діюча гарантія; її термін визначає trigger_seconds, не cleanup."""
    from morok_relay.cleanup import reap_terminal_dms

    now = int(time.time())
    db.add(DeadManSwitch(
        id=uuid.uuid4(), creator_pubkey=b"\x03" * 32,
        trigger_seconds=3600, last_check_in_at=now - 999999,
        payload_encrypted=b"\x01" * 100, status=DMSStatus.ARMED,
        created_at=now - 999999,
    ))
    await db.commit()

    removed = await reap_terminal_dms(db)
    await db.commit()
    assert removed == 0
