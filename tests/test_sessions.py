"""
Tests for morok_relay.sessions.

Requires a running local Redis. If you don't have one, skip with:
    pytest tests/test_sessions.py -k "not real_redis"

We use Redis DB 15 to avoid clashing with the dev DB (0). It's wiped before
each test.
"""
from __future__ import annotations

import os

import pytest
import redis.asyncio as redis_async

from morok_relay.sessions import (
    consume_challenge,
    create_session,
    generate_token,
    revoke_all_sessions,
    revoke_session,
    store_challenge,
    verify_session_token,
)

# Use a separate Redis DB for tests so we don't trample dev data.
TEST_REDIS_URL = os.getenv("MOROK_TEST_REDIS_URL", "redis://localhost:6379/15")


@pytest.fixture
async def redis():
    """Provide a clean Redis client for each test."""
    client = redis_async.from_url(TEST_REDIS_URL, decode_responses=False)
    await client.flushdb()
    yield client
    await client.flushdb()
    await client.aclose()


# ============================================================================
# Token generation
# ============================================================================

def test_token_is_hex_64_chars():
    t = generate_token()
    assert len(t) == 64
    assert all(c in "0123456789abcdef" for c in t)


def test_tokens_are_unique():
    tokens = {generate_token() for _ in range(1000)}
    assert len(tokens) == 1000


# ============================================================================
# Session lifecycle
# ============================================================================

@pytest.mark.asyncio
async def test_create_and_verify_session(redis):
    pubkey = "a" * 64
    session = await create_session(redis, pubkey)

    verified = await verify_session_token(redis, session.token)
    assert verified is not None
    assert verified.pubkey_hex == pubkey
    assert verified.token == session.token


@pytest.mark.asyncio
async def test_verify_unknown_token_returns_none(redis):
    result = await verify_session_token(redis, "deadbeef" * 8)
    assert result is None


@pytest.mark.asyncio
async def test_verify_empty_token_returns_none(redis):
    assert await verify_session_token(redis, "") is None


@pytest.mark.asyncio
async def test_revoke_session_makes_it_invalid(redis):
    pubkey = "b" * 64
    session = await create_session(redis, pubkey)

    # Confirm valid first
    assert await verify_session_token(redis, session.token) is not None

    # Revoke
    revoked = await revoke_session(redis, session.token)
    assert revoked is True

    # Now invalid
    assert await verify_session_token(redis, session.token) is None


@pytest.mark.asyncio
async def test_revoke_unknown_token_returns_false(redis):
    assert await revoke_session(redis, "f" * 64) is False


@pytest.mark.asyncio
async def test_revoke_all_sessions(redis):
    pubkey = "c" * 64
    s1 = await create_session(redis, pubkey)
    s2 = await create_session(redis, pubkey)
    s3 = await create_session(redis, pubkey)

    # Different pubkey — must survive
    other = await create_session(redis, "d" * 64)

    count = await revoke_all_sessions(redis, pubkey)
    assert count == 3

    # All revoked
    assert await verify_session_token(redis, s1.token) is None
    assert await verify_session_token(redis, s2.token) is None
    assert await verify_session_token(redis, s3.token) is None

    # Other pubkey unaffected
    assert await verify_session_token(redis, other.token) is not None


# ============================================================================
# Challenge storage
# ============================================================================

@pytest.mark.asyncio
async def test_consume_challenge_returns_pubkey(redis):
    challenge = "aa" * 32
    pubkey = "11" * 32

    await store_challenge(redis, challenge, pubkey)
    result = await consume_challenge(redis, challenge)
    assert result == pubkey


@pytest.mark.asyncio
async def test_consume_challenge_is_one_time_use(redis):
    challenge = "bb" * 32
    pubkey = "22" * 32

    await store_challenge(redis, challenge, pubkey)
    first = await consume_challenge(redis, challenge)
    second = await consume_challenge(redis, challenge)

    assert first == pubkey
    assert second is None  # replay returns None


@pytest.mark.asyncio
async def test_consume_unknown_challenge(redis):
    assert await consume_challenge(redis, "zz" * 32) is None
