"""
Group inbox cap не був атомарним (жорсткий свіжий прохід — GPT-
перегляд другого раунду).

Знахідка: для звичайного DM check-then-insert вже виправлений через
атомарний Lua (_INBOX_ENQUEUE_LUA). Але групового fan-out це не
стосувалось: окремий pipeline читав ZCARD усіх учасників, формував
eligible, а вже ПІЗНІШЕ, іншим pipeline, робив ZADD. Два одночасні
group sends могли обидва побачити 4999<5000 для того самого
recipient'а і обидва вставитись — MAX_INBOX_QUEUE_DEPTH=5000
"hard cap" на практиці не був hard.

Фікс: та сама атомарна Lua, що вже перевірена для DM, для КОЖНОГО
recipient'а окремо, батчовано в одному pipeline round-trip.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from morok_relay import queue as q

pytestmark = pytest.mark.asyncio

SENDER = "11" * 32
RECIPIENT = "aa" * 32


async def _fanout(redis, eid: str, recipients: list[str]):
    return await q.enqueue_envelope_for_recipients(
        redis=redis, envelope_id=eid, sender_pubkey_hex=SENDER,
        recipient_pubkeys_hex=recipients,
        timestamp=int(time.time()), ttl_seconds=3600,
        signature_hex="ff" * 64, hard_ceiling_seconds=86400,
        group_id="g1",
    )


# ── звичайний шлях ────────────────────────────────────────────────────────
async def test_normal_fanout_still_works(redis):
    eid = "aa" * 32
    expires_at, count = await _fanout(redis, eid, ["11" * 32, "22" * 32])
    assert count == 2
    assert expires_at > 0


async def test_full_inbox_recipient_skipped_not_whole_send_refused(
    redis, monkeypatch,
):
    """Контроль: переповнений одержувач пропускається, решта групи
    досі отримує повідомлення — вся суть group fan-out, не зламана
    новим EVAL-based підходом."""
    monkeypatch.setattr(q, "MAX_INBOX_QUEUE_DEPTH", 1)
    full_recipient = "bb" * 32
    now = int(time.time())
    await redis.zadd(f"morok:inbox:{full_recipient}", {"existing": now + 3600})

    eid = "bb" * 32
    _, count = await _fanout(redis, eid, [full_recipient, "cc" * 32])
    assert count == 1

    depth_full = await redis.zcard(f"morok:inbox:{full_recipient}")
    assert depth_full == 1, "переповнений одержувач отримав другий конверт"
    depth_ok = await redis.zcard(f"morok:inbox:{'cc' * 32}")
    assert depth_ok == 1


# ── fail-open fallback при повному збої Redis ─────────────────────────────
async def test_redis_failure_falls_back_to_unconditional_insert(
    redis, monkeypatch,
):
    """Якщо ВЕСЬ EVAL-пакет провалюється (Redis-збій), fail-open
    fallback має вставити напряму для ВСІХ — не мовчки загубити
    групову розсилку через блимок Redis."""
    real_pipeline = redis.pipeline
    call_count = {"n": 0}

    def failing_first_pipeline(*a, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise ConnectionError("redis down")
        return real_pipeline(*a, **kw)

    monkeypatch.setattr(redis, "pipeline", failing_first_pipeline)

    eid = "cc" * 32
    expires_at, count = await _fanout(redis, eid, ["dd" * 32, "ee" * 32])
    assert count == 2, "fail-open fallback мав вставити для всіх"

    depth1 = await redis.zcard(f"morok:inbox:{'dd' * 32}")
    depth2 = await redis.zcard(f"morok:inbox:{'ee' * 32}")
    assert depth1 == 1
    assert depth2 == 1


# ── справжня паралельна гонка ─────────────────────────────────────────────
async def test_concurrent_group_sends_never_exceed_cap_for_shared_recipient(
    redis,
):
    """
    ГОЛОВНИЙ ТЕСТ. Один спільний recipient (наприклад, учасник кількох
    активних груп) отримує ОДНОЧАСНО 10 різних групових розсилок,
    маючи місце рівно під ліміт (MAX-1 вже зайнято). Атомарно має
    пройти рівно один fan-out для нього.
    """
    monkeypatch_depth = 5
    import morok_relay.queue as qmod
    orig_depth = qmod.MAX_INBOX_QUEUE_DEPTH
    qmod.MAX_INBOX_QUEUE_DEPTH = monkeypatch_depth
    try:
        shared_recipient = "ff" * 32
        now = int(time.time())
        for i in range(monkeypatch_depth - 1):
            await redis.zadd(
                f"morok:inbox:{shared_recipient}",
                {f"pre-existing-{i}": now + 3600},
            )

        async def try_fanout(i: int):
            eid = f"{i:064x}"
            return await _fanout(redis, eid, [shared_recipient])

        results = await asyncio.gather(*[try_fanout(i) for i in range(10)])
        accepted = sum(1 for _, count in results if count == 1)

        assert accepted == 1, \
            f"прийнято {accepted} fan-out'ів на спільного одержувача " \
            f"замість рівно 1 — group cap race"

        final_depth = await redis.zcard(f"morok:inbox:{shared_recipient}")
        assert final_depth == monkeypatch_depth
    finally:
        qmod.MAX_INBOX_QUEUE_DEPTH = orig_depth
