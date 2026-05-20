"""
Tests for federation lookup retry + cache logic.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def test_users_module_imports():
    from morok_relay.api import users
    assert hasattr(users, "_remote_lookup_with_retry")
    assert hasattr(users, "_get_lookup_cache")
    assert hasattr(users, "_set_lookup_cache")
    assert users.FED_LOOKUP_CACHE_TTL_SECONDS == 24 * 3600
    assert users.FED_LOOKUP_RETRY_DELAYS == (0.5, 1.0, 2.0)


def test_lookup_cache_key_format():
    from morok_relay.api.users import _lookup_cache_key
    key = _lookup_cache_key("relay2.morok.app", "vasya")
    assert key == "morok:fed_lookup:relay2.morok.app:vasya"


@pytest.mark.asyncio
async def test_get_lookup_cache_returns_none_on_miss():
    from morok_relay.api.users import _get_lookup_cache

    redis = MagicMock()
    redis.get = AsyncMock(return_value=None)

    result = await _get_lookup_cache(redis, "relay2.morok.app", "missing")
    assert result is None


@pytest.mark.asyncio
async def test_get_lookup_cache_parses_hit():
    from morok_relay.api.users import _get_lookup_cache

    payload = {
        "pubkey_hex": "ab" * 32,
        "username": "vasya",
        "home_relay": "relay2.morok.app",
    }
    redis = MagicMock()
    redis.get = AsyncMock(return_value=json.dumps(payload).encode())

    result = await _get_lookup_cache(redis, "relay2.morok.app", "vasya")
    assert result == payload


@pytest.mark.asyncio
async def test_get_lookup_cache_fail_open():
    """If Redis blips, treat as cache miss (return None)."""
    from morok_relay.api.users import _get_lookup_cache

    redis = MagicMock()
    redis.get = AsyncMock(side_effect=ConnectionError("redis down"))

    result = await _get_lookup_cache(redis, "relay2.morok.app", "vasya")
    assert result is None


@pytest.mark.asyncio
async def test_remote_lookup_retry_succeeds_first_try():
    from morok_relay.api import users

    expected = {"pubkey_hex": "ab" * 32, "username": "vasya",
                "home_relay": "relay2.morok.app"}

    with patch.object(users, "remote_lookup",
                      new=AsyncMock(return_value=expected)):
        result = await users._remote_lookup_with_retry(
            "relay2.morok.app", "vasya",
        )
    assert result == expected


@pytest.mark.asyncio
async def test_remote_lookup_retry_marks_not_found():
    """When remote_lookup returns None, we mark __not_found."""
    from morok_relay.api import users

    with patch.object(users, "remote_lookup", new=AsyncMock(return_value=None)):
        result = await users._remote_lookup_with_retry(
            "relay2.morok.app", "ghost",
        )
    assert result == {"__not_found": True}


@pytest.mark.asyncio
async def test_remote_lookup_retry_all_attempts_fail():
    """When all retries raise, return None (peer unreachable)."""
    from morok_relay.api import users

    with patch.object(users, "remote_lookup",
                      new=AsyncMock(side_effect=ConnectionError("nope"))):
        result = await users._remote_lookup_with_retry(
            "relay2.morok.app", "vasya",
        )
    assert result is None
