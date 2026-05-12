"""
Tests for morok_relay.queue.

Requires a running local Redis (uses DB 15 to avoid stepping on dev data).
"""
from __future__ import annotations

import os

import pytest
import redis.asyncio as redis_async

from morok_relay.queue import (
    acknowledge_envelope,
    enqueue_envelope,
    envelope_exists,
    list_inbox,
)

TEST_REDIS_URL = os.getenv("MOROK_TEST_REDIS_URL", "redis://localhost:6379/15")


@pytest.fixture
async def redis():
    client = redis_async.from_url(TEST_REDIS_URL, decode_responses=False)
    await client.flushdb()
    yield client
    await client.flushdb()
    await client.aclose()


@pytest.mark.asyncio
async def test_enqueue_and_list(redis):
    expires = await enqueue_envelope(
        redis=redis,
        envelope_id="aa" * 32,
        sender_pubkey_hex="11" * 32,
        recipient_pubkey_hex="22" * 32,
        timestamp=1_700_000_000,
        ttl_seconds=3600,
        signature_hex="cc" * 64,
        hard_ceiling_seconds=172800,
    )
    assert expires > 0

    pending = await list_inbox(redis, "22" * 32)
    assert len(pending) == 1
    assert pending[0]["envelope_id"] == "aa" * 32
    assert pending[0]["from"] == "11" * 32


@pytest.mark.asyncio
async def test_dedup_envelope_exists(redis):
    eid = "bb" * 32
    assert await envelope_exists(redis, eid) is False
    await enqueue_envelope(
        redis=redis,
        envelope_id=eid,
        sender_pubkey_hex="11" * 32,
        recipient_pubkey_hex="22" * 32,
        timestamp=1_700_000_000,
        ttl_seconds=3600,
        signature_hex="cc" * 64,
        hard_ceiling_seconds=172800,
    )
    assert await envelope_exists(redis, eid) is True


@pytest.mark.asyncio
async def test_acknowledge_removes_from_inbox(redis):
    eid = "dd" * 32
    recipient = "ee" * 32
    await enqueue_envelope(
        redis=redis,
        envelope_id=eid,
        sender_pubkey_hex="11" * 32,
        recipient_pubkey_hex=recipient,
        timestamp=1_700_000_000,
        ttl_seconds=3600,
        signature_hex="cc" * 64,
        hard_ceiling_seconds=172800,
    )
    assert len(await list_inbox(redis, recipient)) == 1

    removed = await acknowledge_envelope(redis, recipient, eid)
    assert removed is True

    assert len(await list_inbox(redis, recipient)) == 0


@pytest.mark.asyncio
async def test_ack_unknown_returns_false(redis):
    removed = await acknowledge_envelope(redis, "ee" * 32, "ff" * 32)
    assert removed is False


@pytest.mark.asyncio
async def test_ttl_capped_at_hard_ceiling(redis):
    """Even if client sends huge TTL, server caps at hard ceiling."""
    import time

    now = int(time.time())
    expires = await enqueue_envelope(
        redis=redis,
        envelope_id="cc" * 32,
        sender_pubkey_hex="11" * 32,
        recipient_pubkey_hex="22" * 32,
        timestamp=now,
        ttl_seconds=999999,            # client asked for huge TTL
        signature_hex="cc" * 64,
        hard_ceiling_seconds=172800,   # but ceiling is 48h
    )
    # Expires must be within (now + ceiling), not (now + 999999)
    assert expires <= now + 172800 + 5  # small slack for execution time


@pytest.mark.asyncio
async def test_inbox_isolated_per_recipient(redis):
    """Sending to recipient A must not appear in recipient B's inbox."""
    await enqueue_envelope(
        redis=redis,
        envelope_id="11" * 32,
        sender_pubkey_hex="00" * 32,
        recipient_pubkey_hex="aa" * 32,
        timestamp=1_700_000_000,
        ttl_seconds=3600,
        signature_hex="cc" * 64,
        hard_ceiling_seconds=172800,
    )

    assert len(await list_inbox(redis, "aa" * 32)) == 1
    assert len(await list_inbox(redis, "bb" * 32)) == 0
