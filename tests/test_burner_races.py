"""
Burner tokens: атомарність лічильника (аудит 3, P1).

Стара реалізація GET→decode→+1→SET дозволяла:
  * двом паралельним відправкам пройти повз ліміт;
  * «воскресіння» токена після revoke (SET повертав metadata,
    видалену конкурентним revoke).
"""
from __future__ import annotations

import asyncio

import pytest

from morok_relay import burner_tokens as bt

pytestmark = pytest.mark.asyncio

OWNER = "aa" * 32


async def test_increment_basic_and_keepttl(redis):
    tok = (await bt.create_token(redis, OWNER, ttl_seconds=3600))["token"]
    ok, count = await bt.increment_message_count(redis, tok)
    assert (ok, count) == (True, 1)
    # KEEPTTL: інкремент не скидає залишок життя токена
    ttl = await redis.ttl(f"morok:burner_token:{tok}")
    assert 3500 < ttl <= 3600


async def test_parallel_sends_respect_cap_exactly(redis):
    """150 паралельних відправок при ліміті 100 → рівно 100 дозволених."""
    tok = (await bt.create_token(redis, OWNER, ttl_seconds=3600))["token"]
    results = await asyncio.gather(
        *[bt.increment_message_count(redis, tok) for _ in range(150)]
    )
    allowed = sum(1 for ok, _ in results if ok)
    assert allowed == bt.MAX_MESSAGES_PER_TOKEN
    # токен auto-revoke'нувся атомарно, включно з reverse-сетом власника
    assert await redis.get(f"morok:burner_token:{tok}") is None
    assert not await redis.sismember(f"morok:burner_owner:{OWNER}", tok)


async def test_no_resurrection_after_revoke(redis):
    """Інкременти паралельно з revoke не повертають токен до життя."""
    tok = (await bt.create_token(redis, "bb" * 32, ttl_seconds=3600))["token"]

    async def spam():
        for _ in range(30):
            await bt.increment_message_count(redis, tok)

    await asyncio.gather(spam(), bt.revoke_token(redis, "bb" * 32, tok), spam())
    assert await redis.get(f"morok:burner_token:{tok}") is None


async def test_missing_token(redis):
    ok, count = await bt.increment_message_count(redis, "no_such_token_xxxx")
    assert (ok, count) == (False, 0)
