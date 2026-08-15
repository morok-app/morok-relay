"""
Пошта: подвійна відправка (аудит 3, P2).

  * outbound_claim: SELECT ... FOR UPDATE SKIP LOCKED — воркер, що
    claim'ить, поки перший ще тримає транзакцію, отримує ТІЛЬКИ
    незалочені рядки. Без цього обидва брали ту саму пачку і лист
    ішов двічі.
  * добова квота compose: pg_advisory_xact_lock серіалізує паралельні
    compose одного акаунта — ліміт не пробивається гонкою COUNT→INSERT.
"""
from __future__ import annotations

import asyncio
import time
import uuid

import pytest
from sqlalchemy import select

from morok_relay.api.mail import _queue_external, outbound_claim
from morok_relay.config import get_settings
from morok_relay.mail_models import (
    AliasStatus,
    MailAlias,
    MailOutbound,
    OutboundStatus,
)

pytestmark = pytest.mark.asyncio

OWNER = bytes.fromhex("66" * 32)
TOKEN = "test-worker-token"  # MOROK_MAIL_OUT_TOKEN з conftest


def _queued_row(i: int) -> MailOutbound:
    now = int(time.time())
    return MailOutbound(
        id=uuid.uuid4(),
        owner_pubkey=OWNER,
        from_alias="tester",
        to_addr=f"dest{i}@example.com",
        subject=f"s{i}",
        body_text="hello",
        status=OutboundStatus.QUEUED,
        attempts=0,
        created_at=now + i,  # стабільний порядок
        updated_at=now,
    )


async def test_two_workers_get_disjoint_batches(pg_sessionmaker):
    """
    Воркер A тримає FOR UPDATE на перших 5 рядках (транзакція відкрита) —
    воркер B, що claim'ить у цей момент, мусить отримати ІНШІ 5.
    Разом — усі 10, без перетину.
    """
    async with pg_sessionmaker() as s:
        for i in range(10):
            s.add(_queued_row(i))
        await s.commit()

    async with pg_sessionmaker() as worker_a:
        locked = (await worker_a.execute(
            select(MailOutbound)
            .where(MailOutbound.status == OutboundStatus.QUEUED)
            .order_by(MailOutbound.created_at)
            .limit(5)
            .with_for_update(skip_locked=True)
        )).scalars().all()
        locked_ids = {str(r.id) for r in locked}
        assert len(locked_ids) == 5

        # Воркер B claim'ить, ПОКИ лок A живий.
        async with pg_sessionmaker() as worker_b:
            resp = await outbound_claim(
                body={"limit": 10}, db=worker_b, x_mailout_token=TOKEN,
            )
        b_ids = {j["id"] for j in resp["jobs"]}

        assert len(b_ids) == 5, f"B взяв {len(b_ids)} рядків замість 5"
        assert not (b_ids & locked_ids), "ПЕРЕТИН: лист піде двічі!"

        await worker_a.rollback()


async def test_claim_marks_sending_and_is_exhaustive(pg_sessionmaker):
    """Два послідовні claim'и разом вигрібають чергу без дублів."""
    async with pg_sessionmaker() as s:
        for i in range(6):
            s.add(_queued_row(i))
        await s.commit()

    async with pg_sessionmaker() as w1:
        r1 = await outbound_claim(body={"limit": 4}, db=w1, x_mailout_token=TOKEN)
    async with pg_sessionmaker() as w2:
        r2 = await outbound_claim(body={"limit": 4}, db=w2, x_mailout_token=TOKEN)

    ids1 = {j["id"] for j in r1["jobs"]}
    ids2 = {j["id"] for j in r2["jobs"]}
    assert len(ids1) == 4 and len(ids2) == 2
    assert not (ids1 & ids2)

    async with pg_sessionmaker() as s:
        sending = (await s.execute(
            select(MailOutbound).where(MailOutbound.status == OutboundStatus.SENDING)
        )).scalars().all()
        assert len(sending) == 6


async def test_bad_worker_token_rejected(pg_sessionmaker):
    from fastapi import HTTPException
    async with pg_sessionmaker() as s:
        with pytest.raises(HTTPException):
            await outbound_claim(body={}, db=s, x_mailout_token="wrong")


async def test_daily_quota_survives_parallel_compose(
    pg_sessionmaker, fake_session, monkeypatch,
):
    """
    Гонка COUNT→INSERT: N паралельних compose при ліміті 3 → у БД
    РІВНО 3 рядки. pg_advisory_xact_lock серіалізує один акаунт.
    """
    settings = get_settings()
    monkeypatch.setattr(settings, "mail_out_user_daily", 3)

    pk_hex = "77" * 32
    async with pg_sessionmaker() as s:
        s.add(MailAlias(
            alias="quota", owner_pubkey=bytes.fromhex(pk_hex),
            status=AliasStatus.ACTIVE, is_primary=True,
        ))
        await s.commit()

    session = fake_session(pk_hex)
    body = {"from_alias": "quota", "subject": "x", "text": "hello"}

    async def one_compose():
        async with pg_sessionmaker() as db:
            try:
                await _queue_external(dict(body), session, db, "out@example.com")
                await db.commit()
                return True
            except Exception:
                await db.rollback()
                return False

    results = await asyncio.gather(*[one_compose() for _ in range(8)])
    assert sum(results) == 3, f"квоту пробито: пройшло {sum(results)} з ліміту 3"

    async with pg_sessionmaker() as s:
        rows = (await s.execute(
            select(MailOutbound).where(
                MailOutbound.owner_pubkey == bytes.fromhex(pk_hex)
            )
        )).scalars().all()
        assert len(rows) == 3
