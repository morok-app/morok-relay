"""
Race check→insert (аудит зовн. №4, MEDIUM) — два незалежні місця:

  1. Inbox depth guard: zremrangebyscore+zcard (перевірка) і zadd
     (вставка) були окремими round-trip. "Hard limit" на практиці
     можна було прострелити паралельними відправниками на одного
     одержувача.
  2. Group capacity: len(group.members) звірявся з уже завантаженим
     списком, INSERT — окремо. Два одночасні add_member на останнє
     вільне місце могли обидва пройти.

Головні тести тут — СПРАВЖНІЙ concurrency: asyncio.gather() із
кількома паралельними викликами навколо межі ліміту, не просто
послідовні виклики (які й старий код витримував би).
"""
from __future__ import annotations

import asyncio
import time
import uuid

import pytest
from fastapi import HTTPException

from morok_relay import queue as q

pytestmark = pytest.mark.asyncio

SENDER = "99" * 32
RECIPIENT = "aa" * 32


def _mk(eid: str, recipient: str = RECIPIENT) -> dict:
    return dict(
        envelope_id=eid,
        sender_pubkey_hex=SENDER,
        recipient_pubkey_hex=recipient,
        timestamp=int(time.time()),
        ttl_seconds=3600,
        signature_hex="ff" * 64,
        hard_ceiling_seconds=86400,
    )


# ── inbox depth: справжня паралельна гонка ───────────────────────────────
async def test_concurrent_enqueue_never_exceeds_hard_limit(redis, monkeypatch):
    """
    ГОЛОВНИЙ ТЕСТ. Ставимо ліміт впритул (5) і одночасно (не послідовно!)
    б'ємо 20 паралельних enqueue на ОДНОГО одержувача. Атомарний EVAL
    мусить пропустити РІВНО 5, решта — EnqueueRejected(429). Старий
    код (окремі zcard+zadd) міг пропустити більше під справжнім
    concurrency — цей тест саме такий сценарій і відтворює.
    """
    monkeypatch.setattr(q, "MAX_INBOX_QUEUE_DEPTH", 5)

    async def try_enqueue(i: int) -> bool:
        try:
            await q.enqueue_envelope(redis, **_mk(f"{i:02x}" * 32))
            return True
        except q.EnqueueRejected:
            return False

    results = await asyncio.gather(*[try_enqueue(i) for i in range(20)])
    accepted = sum(results)

    assert accepted == 5, \
        f"прийнято {accepted} конвертів замість рівно 5 — hard limit не hard"

    depth = await redis.zcard(f"morok:inbox:{RECIPIENT}")
    assert depth == 5, f"фактична глибина черги {depth} != заявленого ліміту"


async def test_concurrent_enqueue_no_orphaned_meta_on_rejection(redis, monkeypatch):
    """
    Для кожного ВІДХИЛЕНОГО конверта meta-запис (SET NX перед EVAL) має
    бути прибраний — інакше сирота висить до власного TTL даремно.
    """
    monkeypatch.setattr(q, "MAX_INBOX_QUEUE_DEPTH", 3)

    eids = [f"{i:03x}" * 21 + "aa" for i in range(10)]

    async def try_enqueue(eid: str) -> bool:
        try:
            await q.enqueue_envelope(redis, **_mk(eid, recipient="bb" * 32))
            return True
        except q.EnqueueRejected:
            return False

    results = await asyncio.gather(*[try_enqueue(e) for e in eids])
    rejected_eids = [e for e, ok in zip(eids, results, strict=False) if not ok]

    assert len(rejected_eids) == 7
    for eid in rejected_eids:
        exists = await redis.exists(f"morok:envelope:{eid}")
        assert not exists, f"осиротіла meta для відхиленого {eid}"


async def test_sequential_enqueue_still_works_normally(redis, monkeypatch):
    """Контроль: звичайний послідовний шлях (не concurrency) поводиться
    як і раніше — приймає до ліміту, відхиляє понад ним."""
    monkeypatch.setattr(q, "MAX_INBOX_QUEUE_DEPTH", 2)

    await q.enqueue_envelope(redis, **_mk("c1" * 32, recipient="cc" * 32))
    await q.enqueue_envelope(redis, **_mk("c2" * 32, recipient="cc" * 32))
    with pytest.raises(q.EnqueueRejected) as e:
        await q.enqueue_envelope(redis, **_mk("c3" * 32, recipient="cc" * 32))
    assert e.value.status_code == 429


async def test_expired_entries_still_pruned_atomically(redis, monkeypatch):
    """prune (zremrangebyscore) досі відбувається — тепер усередині
    EVAL, а не окремим клієнтським викликом."""
    monkeypatch.setattr(q, "MAX_INBOX_QUEUE_DEPTH", 3)
    recipient = "dd" * 32
    past = int(time.time()) - 100
    await redis.zadd(f"morok:inbox:{recipient}", {"stale-entry": past})

    await q.enqueue_envelope(redis, **_mk("e1" * 32, recipient=recipient))

    members = {
        m.decode() for m in await redis.zrange(f"morok:inbox:{recipient}", 0, -1)
    }
    assert "stale-entry" not in members


# ── group capacity: справжня паралельна гонка ────────────────────────────
async def test_concurrent_add_member_never_exceeds_max(pg_sessionmaker):
    """
    ГОЛОВНИЙ ТЕСТ. Група з max_members=3, один слот вільний. П'ять
    одночасних add_member на п'ять РІЗНИХ кандидатів — атомарно (row
    lock) має пройти рівно один.

    Кожен паралельний виклик отримує ВЛАСНУ AsyncSession з пулу
    (pg_sessionmaker) — так само, як у проді кожен HTTP-запит має
    власну сесію. Спільна сесія (звичайна `db`-фікстура) не є
    concurrency-safe для одночасних await'ів і не відтворює реальний
    race — саме тому тут окремий підхід.
    """
    from morok_relay.api.groups import add_member
    from morok_relay.models import Group, GroupMember
    from morok_relay.schemas import GroupAddMemberRequest
    from morok_relay.sessions import Session

    admin_pk_hex = "11" * 32
    now = int(time.time())
    gid = uuid.uuid4()

    async with pg_sessionmaker() as setup_db:
        group = Group(
            id=gid, creator_pubkey=bytes.fromhex(admin_pk_hex),
            name_encrypted=b"\x01" * 32, is_channel=False,
            default_ttl_seconds=86400, anonymous_senders=False,
            max_members=3, created_at=now,
        )
        group.members.append(GroupMember(
            id=uuid.uuid4(), pubkey=bytes.fromhex(admin_pk_hex),
            is_admin=True, joined_at=now,
        ))
        group.members.append(GroupMember(
            id=uuid.uuid4(), pubkey=b"\x02" * 32, is_admin=False, joined_at=now,
        ))
        setup_db.add(group)
        await setup_db.commit()

    session = Session(token="t" * 64, pubkey_hex=admin_pk_hex, expires_at=2**31)
    candidates = [f"{i:064x}" for i in range(10, 15)]  # 5 різних кандидатів

    # Штучна синхронізаційна затримка: без неї 5 паралельних asyncio-
    # задач на локальному Postgres (дуже швидкий round-trip) можуть
    # випадково НЕ перетнутись у критичній секції — кожна встигає
    # завершитись раніше, ніж наступна дійде до capacity-check, і race
    # window просто не проявляється, незалежно від того, є фікс чи
    # немає. bar гарантує, що всі 5 задач дійдуть до перевірки capacity
    # ОДНОЧАСНО, відтворюючи справжню гонку детерміновано.
    barrier = asyncio.Barrier(len(candidates))

    import morok_relay.api.groups as groups_mod
    real_load_group = groups_mod._load_group

    async def synced_load_group(db_, gid_):
        result = await real_load_group(db_, gid_)
        await barrier.wait()
        return result

    async def try_add(pk_hex: str) -> bool:
        # Явний commit після add_member — емулюємо поведінку продакшн
        # DBSession dependency (get_session, db.py), яка комітить у
        # кінці HTTP-запиту. add_member сам робить лише flush(); без
        # явного коміту тут кожна паралельна "транзакція" лишається
        # невидимою для інших, FOR UPDATE лок ні на що не впливає, і
        # тест хибно показував би "усі проходять" незалежно від фіксу.
        async with pg_sessionmaker() as own_db:
            try:
                await add_member(
                    str(gid), GroupAddMemberRequest(pubkey_hex=pk_hex),
                    session, own_db,
                )
                await own_db.commit()
                return True
            except HTTPException:
                await own_db.rollback()
                return False

    groups_mod._load_group = synced_load_group
    try:
        results = await asyncio.gather(*[try_add(pk) for pk in candidates])
    finally:
        groups_mod._load_group = real_load_group
    accepted = sum(results)

    assert accepted == 1, \
        f"прийнято {accepted} нових членів замість рівно 1 — capacity race"

    from sqlalchemy import func, select
    async with pg_sessionmaker() as check_db:
        count = (await check_db.execute(
            select(func.count()).select_from(GroupMember)
            .where(GroupMember.group_id == gid)
        )).scalar_one()
    assert count == 3, f"фактична кількість членів {count} != max_members"


async def test_add_member_still_works_normally(db):
    """Контроль: звичайний одиночний add_member не зламаний row-locking."""
    from morok_relay.api.groups import add_member
    from morok_relay.models import Group, GroupMember
    from morok_relay.schemas import GroupAddMemberRequest
    from morok_relay.sessions import Session

    admin_pk_hex = "22" * 32
    now = int(time.time())
    gid = uuid.uuid4()
    group = Group(
        id=gid, creator_pubkey=bytes.fromhex(admin_pk_hex),
        name_encrypted=b"\x01" * 32, is_channel=False,
        default_ttl_seconds=86400, anonymous_senders=False,
        max_members=10, created_at=now,
    )
    group.members.append(GroupMember(
        id=uuid.uuid4(), pubkey=bytes.fromhex(admin_pk_hex),
        is_admin=True, joined_at=now,
    ))
    db.add(group)
    await db.commit()

    session = Session(token="t" * 64, pubkey_hex=admin_pk_hex, expires_at=2**31)
    result = await add_member(
        str(gid), GroupAddMemberRequest(pubkey_hex="33" * 32), session, db,
    )
    assert result.member_count == 2
