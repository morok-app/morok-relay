"""
DMS: гонки check-in ↔ reaper (аудит 3) + повний inbox при спрацюванні.

Найстрашніший сценарій, який закривав аудит: користувач check-in'иться
(«я живий»), його транзакція комітиться — а reaper, що вже прочитав
старі дані, все одно розсилає секрет. Тепер:
  * умова «прострочено» рахується в SQL на свіжих даних;
  * reaper бере FOR UPDATE SKIP LOCKED — DMS, який саме зараз редагує
    користувач, пропускається до наступного запуску;
  * check-in/cancel беруть FOR UPDATE — під час firing чекають і бачать
    уже TRIGGERED.

Плюс: переповнений inbox одержувача при firing → EnqueueRejected
ловиться per-recipient, DMS лишається ARMED і ретраїться, а не
«позначений triggered із загубленим payload'ом».
"""
from __future__ import annotations

import time
import uuid

import pytest
from sqlalchemy import select

from morok_relay.models import DeadManSwitch, DMSRecipient, DMSStatus

pytestmark = pytest.mark.asyncio

CREATOR = bytes.fromhex("44" * 32)
RECIP = bytes.fromhex("55" * 32)


def _armed_dms(overdue_by: int = 100) -> DeadManSwitch:
    now = int(time.time())
    dms = DeadManSwitch(
        id=uuid.uuid4(),
        creator_pubkey=CREATOR,
        trigger_seconds=3600,
        last_check_in_at=now - 3600 - overdue_by,
        payload_encrypted=b"\x01" * 64,
        label="test",
        status=DMSStatus.ARMED,
        created_at=now,
    )
    dms.recipients.append(
        DMSRecipient(id=uuid.uuid4(), recipient_pubkey=RECIP)
    )
    return dms


async def _run_reaper(monkeypatch, pg_sessionmaker, deliver=None):
    """fire_dms_switches із тестовою session_factory і (за потреби)
    підміненою доставкою."""
    from morok_relay import db as dbmod
    from morok_relay.scripts import dms_reaper

    monkeypatch.setattr(dbmod, "_session_factory", pg_sessionmaker)
    if deliver is not None:
        monkeypatch.setattr(dms_reaper, "_build_and_deliver_envelope", deliver)
    return await dms_reaper.fire_dms_switches()


async def test_reaper_fires_overdue(monkeypatch, pg_sessionmaker, redis):
    async with pg_sessionmaker() as s:
        dms = _armed_dms()
        s.add(dms)
        await s.commit()
        did = dms.id

    delivered = []

    async def fake_deliver(**kw):
        delivered.append(kw["recipient_pubkey"])

    stats = await _run_reaper(monkeypatch, pg_sessionmaker, fake_deliver)
    assert stats["dms_fired"] == 1
    assert delivered == [RECIP]

    async with pg_sessionmaker() as s:
        row = (await s.execute(
            select(DeadManSwitch).where(DeadManSwitch.id == did)
        )).scalar_one()
        assert row.status == DMSStatus.TRIGGERED


async def test_fresh_checkin_not_fired(monkeypatch, pg_sessionmaker, redis):
    """Не прострочений DMS не потрапляє навіть у вибірку (умова в SQL)."""
    async with pg_sessionmaker() as s:
        dms = _armed_dms()
        dms.last_check_in_at = int(time.time())  # щойно check-in
        s.add(dms)
        await s.commit()

    stats = await _run_reaper(monkeypatch, pg_sessionmaker,
                              lambda **kw: (_ for _ in ()).throw(AssertionError))
    assert stats["dms_fired"] == 0
    assert stats["dms_scanned"] == 0


async def test_checkin_lock_makes_reaper_skip(monkeypatch, pg_sessionmaker, redis):
    """
    ГОНКА, ЯКУ ЛОВИВ АУДИТ: користувач тримає FOR UPDATE (check-in у
    польоті), reaper запускається — SKIP LOCKED мусить пропустити цей
    DMS. Після коміту check-in'а DMS не прострочений і не firing'ується.
    """
    async with pg_sessionmaker() as s:
        dms = _armed_dms()
        s.add(dms)
        await s.commit()
        did = dms.id

    fired_payloads = []

    async def fake_deliver(**kw):
        fired_payloads.append(kw)

    # Сесія користувача: бере рядок під FOR UPDATE і «думає» (транзакція
    # відкрита), імітуючи check-in у польоті.
    async with pg_sessionmaker() as user_s:
        row = (await user_s.execute(
            select(DeadManSwitch)
            .where(DeadManSwitch.id == did)
            .with_for_update()
        )).scalar_one()

        # Reaper працює ПАРАЛЕЛЬНО, поки лок тримається.
        stats = await _run_reaper(monkeypatch, pg_sessionmaker, fake_deliver)
        assert stats["dms_fired"] == 0, "reaper не пропустив залочений DMS"
        assert fired_payloads == [], "секрет розіслано попри check-in у польоті!"

        # користувач завершує check-in
        row.last_check_in_at = int(time.time())
        await user_s.commit()

    # Наступний запуск reaper'а: DMS свіжий → не спрацьовує.
    stats = await _run_reaper(monkeypatch, pg_sessionmaker, fake_deliver)
    assert stats["dms_fired"] == 0
    assert fired_payloads == []


async def test_full_inbox_keeps_dms_armed_for_retry(
    monkeypatch, pg_sessionmaker, redis
):
    """
    Inbox одержувача повний → доставка кидає EnqueueRejected → DMS
    ЛИШАЄТЬСЯ ARMED (ретрай наступним запуском), а не «triggered із
    загубленим payload'ом». Другий запуск із вільним inbox — доставляє.
    """
    async with pg_sessionmaker() as s:
        dms = _armed_dms()
        s.add(dms)
        await s.commit()
        did = dms.id

    from morok_relay.queue import EnqueueRejected

    attempts = {"n": 0}

    async def deliver_full_then_ok(**kw):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise EnqueueRejected(429, "recipient_queue_full")

    stats = await _run_reaper(monkeypatch, pg_sessionmaker, deliver_full_then_ok)
    assert stats["dms_fired"] == 0
    assert stats["errors"] == 1

    async with pg_sessionmaker() as s:
        row = (await s.execute(
            select(DeadManSwitch).where(DeadManSwitch.id == did)
        )).scalar_one()
        assert row.status == DMSStatus.ARMED, "DMS втрачено при повному inbox"

    # ретрай: inbox «звільнився»
    stats = await _run_reaper(monkeypatch, pg_sessionmaker, deliver_full_then_ok)
    assert stats["dms_fired"] == 1
    assert attempts["n"] == 2
