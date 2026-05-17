"""
Redis-based rate limiting for FastAPI endpoints.

Design
------
Simple per-minute bucket counter in Redis. Each (bucket, identifier) pair
gets a key like `morok:ratelimit:auth:1.2.3.4:1747838460` where the suffix
is the current minute (epoch // 60). INCR + EXPIRE 60s.

If the count exceeds the configured limit, we return 429 with a
Retry-After header pointing at the next minute boundary.

This is a fixed-window counter (not sliding). A burst right at the
boundary CAN get 2x the limit (15:59:59 + 16:00:00). Acceptable for
our threat model — we're stopping spam, not enforcing financial QoS.

Identifiers
-----------
- For unauthenticated endpoints: IP address (from X-Real-IP header set
  by nginx, fallback to request.client.host).
- For authenticated endpoints: pubkey_hex (from session).

Disable
-------
Set `RATE_LIMIT_ENABLED=false` in .env to disable entirely (e.g. for
running the test client locally without hitting limits).
"""
from __future__ import annotations

import logging
import time
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from redis.asyncio import Redis

from .config import get_settings
from .db import get_redis

logger = logging.getLogger(__name__)


# ============================================================================
# Identifier extraction
# ============================================================================

def get_ip_from_request(request: Request) -> str:
    """
    Extract the client's IP. Trusts X-Real-IP set by nginx.

    In nginx config we have `proxy_set_header X-Real-IP $remote_addr` so this
    is reliable. Without nginx, falls back to request.client.host.
    """
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    if request.client:
        return request.client.host

    return "unknown"


# ============================================================================
# Core check
# ============================================================================

async def check_rate_limit(
    redis: Redis,
    bucket: str,
    identifier: str,
    limit_per_minute: int,
) -> tuple[bool, int, int]:
    """
    Check and increment a rate-limit counter.

    Returns: (allowed, current_count, retry_after_seconds)
    - allowed: True if request is within limit
    - current_count: how many requests in this minute window
    - retry_after_seconds: how many seconds until window resets

    Bucket = logical name like "auth", "messages", "groups_create".
    Identifier = IP or pubkey_hex.
    """
    settings = get_settings()
    if not settings.rate_limit_enabled:
        return True, 0, 0

    now = int(time.time())
    minute_window = now // 60
    retry_after = 60 - (now % 60)

    key = f"morok:ratelimit:{bucket}:{identifier}:{minute_window}"

    try:
        async with redis.pipeline(transaction=False) as pipe:
            pipe.incr(key)
            pipe.expire(key, 90)  # 90s > 60s to outlive the window safely
            results = await pipe.execute()
        count = results[0]
    except Exception as e:
        # Redis hiccup — fail OPEN. Rate limiting is defense-in-depth, not
        # a hard auth boundary. Failing closed would DoS ourselves whenever
        # Redis blips.
        logger.warning("Rate limit check failed (failing open): %s", e)
        return True, 0, 0

    allowed = count <= limit_per_minute
    return allowed, count, retry_after


def _raise_rate_limited(retry_after: int, bucket: str, current: int, limit: int):
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"rate_limited_{bucket}_{current}_of_{limit}_per_minute",
        headers={"Retry-After": str(retry_after)},
    )


# ============================================================================
# FastAPI dependency factory
# ============================================================================

def rate_limit_by_ip(bucket: str, limit_per_minute: int):
    """
    Dependency factory for IP-based rate limiting (unauthenticated endpoints).

    Usage:
        @router.post("/challenge", dependencies=[Depends(rate_limit_by_ip("auth", 10))])
        async def challenge(...): ...
    """
    async def _dep(
        request: Request,
        redis: Annotated[Redis, Depends(get_redis)],
    ) -> None:
        ip = get_ip_from_request(request)
        allowed, count, retry_after = await check_rate_limit(
            redis, bucket, ip, limit_per_minute,
        )
        if not allowed:
            logger.info(
                "Rate-limited IP %s on bucket=%s (%d/min, limit=%d)",
                ip, bucket, count, limit_per_minute,
            )
            _raise_rate_limited(retry_after, bucket, count, limit_per_minute)
    return _dep


def rate_limit_by_pubkey(bucket: str, limit_per_minute: int):
    """
    Dependency factory for pubkey-based rate limiting (authenticated endpoints).

    Requires the endpoint to also depend on CurrentSession.

    Usage:
        @router.post(
            "/messages",
            dependencies=[Depends(rate_limit_by_pubkey("messages", 60))],
        )
        async def send(current: CurrentSession, ...): ...
    """
    # Import here to avoid circular import at module load time.
    from .deps import get_current_session

    async def _dep(
        session = Depends(get_current_session),
        redis: Annotated[Redis, Depends(get_redis)] = None,
    ) -> None:
        allowed, count, retry_after = await check_rate_limit(
            redis, bucket, session.pubkey_hex, limit_per_minute,
        )
        if not allowed:
            logger.info(
                "Rate-limited pubkey %s on bucket=%s (%d/min, limit=%d)",
                session.pubkey_hex[:16], bucket, count, limit_per_minute,
            )
            _raise_rate_limited(retry_after, bucket, count, limit_per_minute)
    return _dep


# ============================================================================
# WebSocket helper — count concurrent connections per pubkey
# ============================================================================

# Key: morok:ws:connections:{pubkey_hex} → set of connection IDs (UUIDs)
# Each connection adds itself on connect, removes on disconnect.
# If set size > limit → reject new connection.

def _ws_connections_key(pubkey_hex: str) -> str:
    return f"morok:ws:connections:{pubkey_hex}"


async def reserve_ws_slot(
    redis: Redis,
    pubkey_hex: str,
    connection_id: str,
    limit: int,
) -> bool:
    """
    Try to reserve a WebSocket connection slot for this pubkey.

    Returns True if reservation succeeded (caller can accept the connection),
    False if too many concurrent connections.

    On True, caller MUST call release_ws_slot() when the connection closes
    (in a finally block).
    """
    settings = get_settings()
    if not settings.rate_limit_enabled:
        return True

    key = _ws_connections_key(pubkey_hex)
    try:
        # Count current connections AFTER adding ours
        async with redis.pipeline(transaction=True) as pipe:
            pipe.sadd(key, connection_id)
            pipe.expire(key, 86400)  # cleanup orphans after 24h
            pipe.scard(key)
            results = await pipe.execute()
        count = results[2]
    except Exception as e:
        logger.warning("WS slot reservation failed (failing open): %s", e)
        return True

    if count > limit:
        # Roll back our addition — we're over the limit
        try:
            await redis.srem(key, connection_id)
        except Exception:
            pass
        return False
    return True


async def release_ws_slot(
    redis: Redis,
    pubkey_hex: str,
    connection_id: str,
) -> None:
    """Release a WebSocket slot when the connection closes."""
    try:
        await redis.srem(_ws_connections_key(pubkey_hex), connection_id)
    except Exception as e:
        logger.warning("WS slot release failed: %s", e)
