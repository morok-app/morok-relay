"""
Admin dashboard API.

PRIVACY NOTE
------------
This module exposes ONLY aggregated counters: registration counts, active
user counts, federation queue health, relay uptime, group/envelope totals.

It MUST NEVER expose who-talks-to-whom, message contents, individual
pubkeys, usernames, or any per-conversation metadata. That would defeat
the sealed-sender / metadata-minimization goals of the project. If you
add a metric here, ask: "does this reveal anything about a specific
user's communication?" If yes — don't.

AUTH
----
Separate username/password (not the Ed25519 identity system). Password is
stored as an Argon2id hash in settings.admin_password_hash. On successful
login we issue a random bearer token stored in Redis with a TTL.
"""
from __future__ import annotations

import logging
import secrets
import time
from typing import Annotated

import httpx
import nacl.exceptions
import nacl.pwhash
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ..config import get_settings
from ..deps import DBSession, RedisClient
from ..models import (
    FederationOutboundQueue,
    FederationPeer,
    FedQueueStatus,
    Group,
    User,
)
from ..rate_limit import rate_limit_by_ip

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin"])

_ADMIN_TOKEN_PREFIX = "morok:admin_session:"


# ============================================================================
# AUTH HELPERS
# ============================================================================

def _verify_password(password: str, stored_hash: str) -> bool:
    if not stored_hash:
        return False
    try:
        nacl.pwhash.verify(stored_hash.encode("utf-8"), password.encode("utf-8"))
        return True
    except (nacl.exceptions.InvalidkeyError, Exception):
        return False


async def _create_admin_token(redis, ttl_seconds: int) -> str:
    token = secrets.token_urlsafe(32)
    await redis.setex(f"{_ADMIN_TOKEN_PREFIX}{token}", ttl_seconds, "1")
    return token


async def _verify_admin_token(redis, token: str) -> bool:
    if not token:
        return False
    try:
        return bool(await redis.exists(f"{_ADMIN_TOKEN_PREFIX}{token}"))
    except Exception:
        return False


async def require_admin(
    redis: RedisClient,
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing_authorization",
            headers={"WWW-Authenticate": "Bearer"},
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_authorization_scheme",
        )
    if not await _verify_admin_token(redis, token.strip()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_or_expired_admin_token",
        )


# ============================================================================
# SCHEMAS
# ============================================================================

class AdminLoginRequest(BaseModel):
    username: str = Field(..., max_length=100)
    password: str = Field(..., max_length=200)


class AdminLoginResponse(BaseModel):
    token: str
    expires_in: int


# ============================================================================
# LOGIN
# ============================================================================

@router.post(
    "/login",
    response_model=AdminLoginResponse,
    summary="Admin login — returns a bearer token",
    dependencies=[Depends(rate_limit_by_ip("admin_login", 5))],
)
async def admin_login(
    body: AdminLoginRequest,
    redis: RedisClient,
) -> AdminLoginResponse:
    settings = get_settings()

    if not settings.admin_username or not settings.admin_password_hash:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="admin_panel_not_configured",
        )

    # Constant-ish time: always check password even if username wrong.
    username_ok = secrets.compare_digest(
        body.username, settings.admin_username
    )
    password_ok = _verify_password(body.password, settings.admin_password_hash)

    if not (username_ok and password_ok):
        # Don't leak which part failed.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_credentials",
        )

    token = await _create_admin_token(redis, settings.admin_session_ttl_seconds)
    logger.info("Admin login successful from configured account")
    return AdminLoginResponse(
        token=token,
        expires_in=settings.admin_session_ttl_seconds,
    )


@router.post(
    "/logout",
    summary="Revoke the current admin token",
    dependencies=[Depends(require_admin)],
)
async def admin_logout(
    redis: RedisClient,
    authorization: Annotated[str | None, Header()] = None,
) -> dict:
    if authorization:
        _, _, token = authorization.partition(" ")
        if token:
            await redis.delete(f"{_ADMIN_TOKEN_PREFIX}{token.strip()}")
    return {"revoked": True}


# ============================================================================
# STATS  (aggregated only — no per-user data)
# ============================================================================

async def _ping_relay(hostname: str) -> dict:
    url = f"https://{hostname}/health"
    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(url)
            latency_ms = round((time.monotonic() - t0) * 1000, 1)
            if r.status_code == 200:
                data = r.json()
                return {
                    "hostname": hostname,
                    "up": True,
                    "latency_ms": latency_ms,
                    "version": data.get("version"),
                }
    except Exception:
        pass
    return {"hostname": hostname, "up": False, "latency_ms": None, "version": None}


@router.get(
    "/stats",
    summary="Aggregated relay statistics (admin only)",
    dependencies=[Depends(require_admin)],
)
async def admin_stats(
    db: DBSession,
    redis: RedisClient,
) -> dict:
    settings = get_settings()
    now = int(time.time())
    day_ago = now - 86400
    week_ago = now - 7 * 86400
    month_ago = now - 30 * 86400

    # ---- Registrations ----
    total_users = (await db.execute(
        select(func.count()).select_from(User).where(User.deleted_at.is_(None))
    )).scalar() or 0
    users_24h = (await db.execute(
        select(func.count()).select_from(User)
        .where(User.deleted_at.is_(None), User.created_at > day_ago)
    )).scalar() or 0
    users_local = (await db.execute(
        select(func.count()).select_from(User)
        .where(User.deleted_at.is_(None), User.home_relay == settings.relay_name)
    )).scalar() or 0

    # ---- Active users (DAU / MAU) ----
    dau = (await db.execute(
        select(func.count()).select_from(User)
        .where(User.last_seen_at.isnot(None), User.last_seen_at > day_ago)
    )).scalar() or 0
    mau = (await db.execute(
        select(func.count()).select_from(User)
        .where(User.last_seen_at.isnot(None), User.last_seen_at > month_ago)
    )).scalar() or 0

    # ---- 7-day registration series ----
    day_bucket = (User.created_at / 86400).label("day")
    series_rows = (await db.execute(
        select(day_bucket, func.count())
        .where(User.deleted_at.is_(None), User.created_at > week_ago)
        .group_by(day_bucket)
        .order_by(day_bucket)
    )).all()
    today_bucket = now // 86400
    by_bucket = {int(d): int(c) for d, c in series_rows}
    reg_series = [
        {"day_offset": -(today_bucket - b), "count": by_bucket.get(b, 0)}
        for b in range(today_bucket - 6, today_bucket + 1)
    ]

    # ---- Federation queue health ----
    fed_rows = (await db.execute(
        select(FederationOutboundQueue.status, func.count())
        .group_by(FederationOutboundQueue.status)
    )).all()
    fed_by_status = {s.value if hasattr(s, "value") else str(s): int(c)
                     for s, c in fed_rows}
    oldest_pending = (await db.execute(
        select(func.min(FederationOutboundQueue.created_at))
        .where(FederationOutboundQueue.status == FedQueueStatus.PENDING)
    )).scalar()
    oldest_pending_age = (now - int(oldest_pending)) if oldest_pending else None

    # ---- Groups ----
    total_groups = (await db.execute(
        select(func.count()).select_from(Group).where(Group.deleted_at.is_(None))
    )).scalar() or 0
    local_groups = (await db.execute(
        select(func.count()).select_from(Group)
        .where(Group.deleted_at.is_(None), Group.home_relay == settings.relay_name)
    )).scalar() or 0

    # ---- Envelopes in flight (approximate, from Redis) ----
    envelopes_in_flight = None
    try:
        cursor = 0
        count = 0
        # Bounded scan so we never block: cap at a few thousand keys.
        for _ in range(20):
            cursor, keys = await redis.scan(
                cursor=cursor, match="morok:envelope:*", count=500
            )
            count += len(keys)
            if cursor == 0:
                break
        envelopes_in_flight = count
    except Exception:
        pass

    # ---- Relay uptime / latency ----
    peers = (await db.execute(select(FederationPeer))).scalars().all()
    relay_health = [{"hostname": settings.relay_name, "up": True,
                     "latency_ms": 0.0, "version": None, "self": True}]
    for p in peers:
        h = await _ping_relay(p.hostname)
        h["self"] = False
        h["trusted"] = p.is_trusted
        relay_health.append(h)

    return {
        "generated_at": now,
        "relay_name": settings.relay_name,
        "registrations": {
            "total": total_users,
            "local": users_local,
            "last_24h": users_24h,
            "series_7d": reg_series,
        },
        "active_users": {"dau": dau, "mau": mau},
        "federation_queue": {
            "by_status": fed_by_status,
            "oldest_pending_age_seconds": oldest_pending_age,
            "dead_letter": fed_by_status.get("dead_letter", 0),
        },
        "groups": {"total": total_groups, "local": local_groups},
        "envelopes_in_flight": envelopes_in_flight,
        "relays": relay_health,
    }
