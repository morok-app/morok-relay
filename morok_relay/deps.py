"""
FastAPI dependency injection helpers.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_redis, get_session
from .sessions import Session, verify_session_token

logger = logging.getLogger(__name__)

# DMS check-in is bumped at most once per this window per pubkey, to avoid
# spawning an unbounded number of background DB-session tasks (one per
# authenticated request). 5 minutes is far finer than DMS needs — it fires
# on inactivity measured in days.
DMS_CHECKIN_THROTTLE_SECONDS = 300


async def _bump_dms_check_in_for_pubkey(pubkey_hex: str) -> None:
    """
    Background task: bump last_check_in_at for all armed DMS owned by pubkey.

    Fire-and-forget. Runs in its own DB session so it doesn't block the
    response. If it fails we log and move on — DMS will eventually fire
    if the user truly is gone.
    """
    try:
        from sqlalchemy import update
        from .db import _session_factory
        from .models import DeadManSwitch, DMSStatus

        if _session_factory is None:
            return

        pubkey = bytes.fromhex(pubkey_hex)
        now = int(time.time())

        async with _session_factory() as db:
            stmt = (
                update(DeadManSwitch)
                .where(
                    DeadManSwitch.creator_pubkey == pubkey,
                    DeadManSwitch.status == DMSStatus.ARMED,
                )
                .values(last_check_in_at=now)
            )
            await db.execute(stmt)
            await db.commit()
    except Exception as e:
        logger.warning("DMS check-in bump failed for %s: %s", pubkey_hex[:16], e)


async def get_current_session(
    redis: Annotated[Redis, Depends(get_redis)],
    authorization: Annotated[str | None, Header()] = None,
) -> Session:
    """
    Extract and verify a session token from the Authorization header.

    Side effect: bumps last_check_in_at for any armed DMS owned by this
    pubkey. This is fire-and-forget — does not block the response.

    Returns the Session if valid; raises 401 otherwise.
    """
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
            headers={"WWW-Authenticate": "Bearer"},
        )

    session = await verify_session_token(redis, token.strip())
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_or_expired_token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Fire-and-forget: bump DMS check-in. THROTTLED to once per
    # DMS_CHECKIN_THROTTLE_SECONDS per pubkey via an atomic Redis SET NX.
    # Without this throttle, every authenticated request spawned an
    # unbounded background task opening its own DB session — a self-DoS
    # vector under load. DMS fires on days/weeks of inactivity, so
    # 5-minute granularity on "user is alive" is more than enough.
    #
    # SET NX returns True only for the FIRST request in the window; all
    # others skip spawning entirely. If Redis is down we skip the bump
    # (fail-safe: a missed check-in only delays nothing — the next
    # request bumps it; DMS won't misfire from one skipped bump).
    try:
        should_bump = await redis.set(
            f"morok:dms:checkin_throttle:{session.pubkey_hex}",
            b"1",
            nx=True,
            ex=DMS_CHECKIN_THROTTLE_SECONDS,
        )
    except Exception:
        should_bump = False
    if should_bump:
        asyncio.create_task(_bump_dms_check_in_for_pubkey(session.pubkey_hex))

    return session


CurrentSession = Annotated[Session, Depends(get_current_session)]
DBSession = Annotated[AsyncSession, Depends(get_session)]
RedisClient = Annotated[Redis, Depends(get_redis)]
