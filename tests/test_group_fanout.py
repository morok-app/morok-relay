"""
Груповий fan-out: вартість і коректність (аудит 4, HIGH-2).

Знахідка: перед розсилкою був цикл із ДВОМА послідовними await на
КОЖНОГО одержувача (zremrangebyscore + zcard). Для групи на 500 осіб —
1000 послідовних round-trip до Redis у межах ОДНОГО запиту на
відправку повідомлення. Сам fanout уже був у pipeline; перевірка
глибини — ні.

Тести фіксують і вартість (кількість round-trip не росте лінійно з
розміром групи), і те, що поведінка eligibility при цьому не змінилась.
"""
from __future__ import annotations

import time

import pytest

from morok_relay import queue as q

pytestmark = pytest.mark.asyncio

SENDER = "99" * 32


def _members(n: int) -> list[str]:
    return [f"{i:064x}" for i in range(1, n + 1)]


async def _fanout(redis, recipients, envelope_id="ab" * 32):
    return await q.enqueue_envelope_for_recipients(
        redis,
        envelope_id=envelope_id,
        sender_pubkey_hex=SENDER,
        recipient_pubkeys_hex=recipients,
        timestamp=int(time.time()),
        ttl_seconds=3600,
        signature_hex="ff" * 64,
        hard_ceiling_seconds=86400,
        group_id="11111111-2222-3333-4444-555555555555",
    )


async def test_fanout_delivers_to_all(redis):
    members = _members(50)
    await _fanout(redis, members)
    for pk in members:
        assert await redis.zcard(f"morok:inbox:{pk}") == 1


async def test_roundtrips_do_not_scale_with_group_size(redis, monkeypatch):
    """
    ГОЛОВНИЙ ТЕСТ HIGH-2. Рахуємо звернення до Redis: між групою на 10 і
    на 200 осіб кількість round-trip має лишитись практично тією самою
    (пачки, не по одному на людину). Зі старим кодом 200 учасників
    давали ~400 зайвих await.
    """
    calls = {"n": 0}
    real_execute = q.redis_async.Redis.execute_command

    async def counting_execute(self, *args, **kwargs):
        calls["n"] += 1
        return await real_execute(self, *args, **kwargs)

    monkeypatch.setattr(q.redis_async.Redis, "execute_command", counting_execute)

    calls["n"] = 0
    await _fanout(redis, _members(10), envelope_id="c1" * 32)
    small = calls["n"]

    calls["n"] = 0
    await _fanout(redis, _members(200), envelope_id="c2" * 32)
    large = calls["n"]

    # Допуск щедрий: важливо, що НЕ 2×N. 200 учасників зі старим кодом
    # дали б ~400+ звернень проти ~20 для 10 осіб.
    assert large <= small + 10, (
        f"round-trip'и ростуть з розміром групи: 10 осіб={small}, "
        f"200 осіб={large} — pipeline не працює"
    )


async def test_full_inbox_recipient_skipped_others_delivered(redis, monkeypatch):
    """
    Поведінка не змінилась: переповнений inbox одного члена не зриває
    розсилку решті — пропускаємо тільки його.
    """
    monkeypatch.setattr(q, "MAX_INBOX_QUEUE_DEPTH", 3)
    members = _members(5)
    flooded = members[2]

    now = int(time.time())
    for i in range(3):
        await redis.zadd(f"morok:inbox:{flooded}", {f"old{i}": now + 3600})

    await _fanout(redis, members)

    for pk in members:
        if pk == flooded:
            assert await redis.zcard(f"morok:inbox:{pk}") == 3  # без нового
        else:
            assert await redis.zcard(f"morok:inbox:{pk}") == 1


async def test_expired_entries_pruned_during_fanout(redis):
    """zremrangebyscore у пачці досі чистить протухле."""
    members = _members(3)
    past = int(time.time()) - 100
    for pk in members:
        await redis.zadd(f"morok:inbox:{pk}", {"stale": past})

    await _fanout(redis, members)

    for pk in members:
        ids = {m.decode() for m in await redis.zrange(f"morok:inbox:{pk}", 0, -1)}
        assert "stale" not in ids
        assert len(ids) == 1


async def test_depth_check_failure_fails_open(redis, monkeypatch):
    """Блимок Redis на перевірці глибини не має губити групову розсилку."""
    original_pipeline = redis.pipeline
    state = {"first": True}

    def flaky_pipeline(*a, **kw):
        if state["first"]:
            state["first"] = False

            class Boom:
                async def __aenter__(self_inner):
                    return self_inner

                async def __aexit__(self_inner, *exc):
                    return False

                def zremrangebyscore(self_inner, *a, **kw):
                    return self_inner

                def zcard(self_inner, *a, **kw):
                    return self_inner

                async def execute(self_inner):
                    raise ConnectionError("redis blip")

            return Boom()
        return original_pipeline(*a, **kw)

    monkeypatch.setattr(redis, "pipeline", flaky_pipeline)

    members = _members(4)
    await _fanout(redis, members)
    for pk in members:
        assert await redis.zcard(f"morok:inbox:{pk}") == 1


async def test_publish_group_gone_is_batched(redis, monkeypatch):
    """publish_group_gone теж не має робити N послідовних publish."""
    calls = {"n": 0}
    real_execute = q.redis_async.Redis.execute_command

    async def counting_execute(self, *args, **kwargs):
        calls["n"] += 1
        return await real_execute(self, *args, **kwargs)

    monkeypatch.setattr(q.redis_async.Redis, "execute_command", counting_execute)

    calls["n"] = 0
    await q.publish_group_gone(redis, _members(100), "gid-1", SENDER)
    assert calls["n"] <= 5, f"{calls['n']} звернень на 100 одержувачів — не пачка"


async def test_publish_group_gone_empty_list(redis):
    await q.publish_group_gone(redis, [], "gid-1", SENDER)
