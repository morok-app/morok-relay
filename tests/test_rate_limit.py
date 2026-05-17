"""
Tests for rate_limit module.

These are import + unit tests. The actual Redis interaction is mocked.
For integration tests, run the client_simulator with rate limits enabled
and try to exceed them.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest


# ============================================================================
# Test that the module imports cleanly
# ============================================================================

def test_rate_limit_module_imports():
    """Just confirm we can import the module without errors."""
    from morok_relay import rate_limit
    assert hasattr(rate_limit, "check_rate_limit")
    assert hasattr(rate_limit, "rate_limit_by_ip")
    assert hasattr(rate_limit, "rate_limit_by_pubkey")
    assert hasattr(rate_limit, "reserve_ws_slot")
    assert hasattr(rate_limit, "release_ws_slot")


# ============================================================================
# IP extraction
# ============================================================================

class TestGetIpFromRequest:
    def test_uses_x_real_ip_when_set(self):
        from morok_relay.rate_limit import get_ip_from_request
        request = MagicMock()
        request.headers = {"x-real-ip": "203.0.113.5"}
        request.client = None
        assert get_ip_from_request(request) == "203.0.113.5"

    def test_strips_whitespace(self):
        from morok_relay.rate_limit import get_ip_from_request
        request = MagicMock()
        request.headers = {"x-real-ip": "  203.0.113.5  "}
        request.client = None
        assert get_ip_from_request(request) == "203.0.113.5"

    def test_falls_back_to_client_host(self):
        from morok_relay.rate_limit import get_ip_from_request
        request = MagicMock()
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "10.0.0.1"
        assert get_ip_from_request(request) == "10.0.0.1"

    def test_unknown_when_no_info(self):
        from morok_relay.rate_limit import get_ip_from_request
        request = MagicMock()
        request.headers = {}
        request.client = None
        assert get_ip_from_request(request) == "unknown"


# ============================================================================
# check_rate_limit — core counter logic
# ============================================================================

@pytest.mark.asyncio
async def test_check_rate_limit_first_request_allowed(monkeypatch):
    from morok_relay import rate_limit

    # Mock settings as enabled
    mock_settings = MagicMock()
    mock_settings.rate_limit_enabled = True
    monkeypatch.setattr(rate_limit, "get_settings", lambda: mock_settings)

    # Mock Redis: pipeline returns count=1 (first request)
    pipe = MagicMock()
    pipe.__aenter__ = AsyncMock(return_value=pipe)
    pipe.__aexit__ = AsyncMock(return_value=None)
    pipe.incr = MagicMock()
    pipe.expire = MagicMock()
    pipe.execute = AsyncMock(return_value=[1, True])

    redis = MagicMock()
    redis.pipeline = MagicMock(return_value=pipe)

    allowed, count, retry = await rate_limit.check_rate_limit(
        redis, "test_bucket", "203.0.113.5", limit_per_minute=10,
    )
    assert allowed is True
    assert count == 1


@pytest.mark.asyncio
async def test_check_rate_limit_over_limit_rejected(monkeypatch):
    from morok_relay import rate_limit

    mock_settings = MagicMock()
    mock_settings.rate_limit_enabled = True
    monkeypatch.setattr(rate_limit, "get_settings", lambda: mock_settings)

    pipe = MagicMock()
    pipe.__aenter__ = AsyncMock(return_value=pipe)
    pipe.__aexit__ = AsyncMock(return_value=None)
    pipe.incr = MagicMock()
    pipe.expire = MagicMock()
    pipe.execute = AsyncMock(return_value=[11, True])  # 11 of 10

    redis = MagicMock()
    redis.pipeline = MagicMock(return_value=pipe)

    allowed, count, retry = await rate_limit.check_rate_limit(
        redis, "test_bucket", "203.0.113.5", limit_per_minute=10,
    )
    assert allowed is False
    assert count == 11


@pytest.mark.asyncio
async def test_check_rate_limit_disabled_always_allows(monkeypatch):
    from morok_relay import rate_limit

    mock_settings = MagicMock()
    mock_settings.rate_limit_enabled = False
    monkeypatch.setattr(rate_limit, "get_settings", lambda: mock_settings)

    redis = MagicMock()

    allowed, count, retry = await rate_limit.check_rate_limit(
        redis, "test_bucket", "203.0.113.5", limit_per_minute=1,
    )
    assert allowed is True
    assert count == 0
    # Should not have called Redis at all
    redis.pipeline.assert_not_called()


@pytest.mark.asyncio
async def test_check_rate_limit_redis_failure_fails_open(monkeypatch):
    """If Redis blips, we allow rather than DoS ourselves."""
    from morok_relay import rate_limit

    mock_settings = MagicMock()
    mock_settings.rate_limit_enabled = True
    monkeypatch.setattr(rate_limit, "get_settings", lambda: mock_settings)

    pipe = MagicMock()
    pipe.__aenter__ = AsyncMock(return_value=pipe)
    pipe.__aexit__ = AsyncMock(return_value=None)
    pipe.execute = AsyncMock(side_effect=ConnectionError("redis down"))

    redis = MagicMock()
    redis.pipeline = MagicMock(return_value=pipe)

    allowed, count, retry = await rate_limit.check_rate_limit(
        redis, "test_bucket", "203.0.113.5", limit_per_minute=10,
    )
    assert allowed is True


# ============================================================================
# Config exposure
# ============================================================================

def test_config_has_rate_limit_fields():
    from morok_relay.config import Settings
    s = Settings()
    assert hasattr(s, "rate_limit_enabled")
    assert hasattr(s, "rate_limit_auth_per_minute")
    assert hasattr(s, "rate_limit_messages_per_minute")
    assert hasattr(s, "rate_limit_group_create_per_minute")
    assert hasattr(s, "rate_limit_group_messages_per_minute")
    assert hasattr(s, "rate_limit_dms_create_per_minute")
    assert hasattr(s, "rate_limit_ws_connections_per_pubkey")


def test_config_rate_limit_defaults():
    from morok_relay.config import Settings
    s = Settings()
    assert s.rate_limit_enabled is True
    assert s.rate_limit_auth_per_minute == 10
    assert s.rate_limit_messages_per_minute == 60
    assert s.rate_limit_group_create_per_minute == 5
    assert s.rate_limit_group_messages_per_minute == 30
    assert s.rate_limit_dms_create_per_minute == 5
    assert s.rate_limit_ws_connections_per_pubkey == 5
