"""
User and username endpoints.

GET    /api/v1/users/me                    — get my profile
POST   /api/v1/users/me/username           — claim a @username
DELETE /api/v1/users/me/username           — release my @username
GET    /api/v1/users/lookup/{username}     — find user by @username (public)
       optional ?relay=hostname            — falls back to federation lookup
                                             and caches the result locally

Username rules per tier (see schemas.TIER_MIN_LENGTH):
- free:    5+ chars
- premium: 3+ chars
- admin:   1+ chars (admin tier is server-side only)

Common to all tiers:
- chars: a-z, 0-9, underscore
- max length: 20
- cannot start with digit or underscore
- cannot be in RESERVED_USERNAMES
- 30-day cooldown after release (only original owner can re-claim)
"""
from __future__ import annotations

import logging
import time

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..config import get_settings
from ..deps import CurrentSession, DBSession
from ..federation_client import remote_lookup
from ..models import User, UsernameHistory, UserTier
from ..schemas import (
    MeInfo,
    UserInfo,
    UsernameClaim,
    UsernameReleaseResponse,
    normalize_username,
    validate_username_for_tier,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["users"])


# ============================================================================
# Helpers
# ============================================================================

async def _get_or_create_user(
    db: DBSession, pubkey_hex: str
) -> User:
    """
    Look up user by pubkey, creating a fresh row if this is their first
    authenticated request. New users default to UserTier.FREE.
    """
    settings = get_settings()
    pubkey_bytes = bytes.fromhex(pubkey_hex)

    stmt = select(User).where(User.pubkey == pubkey_bytes)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is not None:
        user.last_seen_at = int(time.time())
        return user

    user = User(
        pubkey=pubkey_bytes,
        home_relay=settings.relay_name,
        tier=UserTier.FREE,
        last_seen_at=int(time.time()),
    )
    db.add(user)
    await db.flush()
    return user


async def _cache_remote_user(
    db: DBSession,
    pubkey_hex: str,
    username: str,
    home_relay: str,
) -> User | None:
    """
    Idempotently create a local User row caching a user we learned about
    from a remote relay. If a row with this pubkey already exists, we
    don't touch it (its local state takes precedence).
    """
    pubkey_bytes = bytes.fromhex(pubkey_hex)

    stmt = select(User).where(User.pubkey == pubkey_bytes)
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing is not None:
        # Don't clobber local state
        return existing

    user = User(
        pubkey=pubkey_bytes,
        username=username,
        home_relay=home_relay,
        tier=UserTier.FREE,  # We don't know remote tier; default
        last_seen_at=None,
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError:
        # Race: username taken, or pubkey collided. Roll back and just
        # return whatever's there now.
        await db.rollback()
        return (await db.execute(stmt)).scalar_one_or_none()
    return user


# ============================================================================
# Endpoints
# ============================================================================

@router.get(
    "/me",
    response_model=MeInfo,
    summary="Get the current user's profile",
)
async def get_me(
    current: CurrentSession,
    db: DBSession,
) -> MeInfo:
    """Return the authenticated user's profile, creating the row if needed."""
    user = await _get_or_create_user(db, current.pubkey_hex)
    return MeInfo(
        pubkey_hex=current.pubkey_hex,
        username=user.username,
        home_relay=user.home_relay,
        tier=user.tier.value,
        created_at=user.created_at,
    )


@router.post(
    "/me/username",
    response_model=MeInfo,
    summary="Claim a @username",
)
async def claim_username(
    body: UsernameClaim,
    current: CurrentSession,
    db: DBSession,
) -> MeInfo:
    """
    Reserve a @username — the requested name must satisfy the caller's tier
    length minimum.

    Errors:
    - 400 invalid_username  : length violates tier minimum, bad chars, reserved
    - 409 username_taken    : someone else has it
    - 409 username_in_cooldown : recently released by different pubkey
    """
    settings = get_settings()
    user = await _get_or_create_user(db, current.pubkey_hex)

    try:
        username = validate_username_for_tier(body.username, user.tier.value)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    pubkey_bytes = bytes.fromhex(current.pubkey_hex)
    now = int(time.time())

    if user.username == username:
        return MeInfo(
            pubkey_hex=current.pubkey_hex,
            username=user.username,
            home_relay=user.home_relay,
            tier=user.tier.value,
            created_at=user.created_at,
        )

    stmt = select(User).where(User.username == username)
    other = (await db.execute(stmt)).scalar_one_or_none()
    if other is not None and other.pubkey != pubkey_bytes:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="username_taken",
        )

    cooldown_seconds = settings.username_cooldown_days * 86400
    cooldown_cutoff = now - cooldown_seconds
    stmt = (
        select(UsernameHistory)
        .where(UsernameHistory.username == username)
        .where(UsernameHistory.released_at >= cooldown_cutoff)
        .order_by(UsernameHistory.released_at.desc())
        .limit(1)
    )
    last_release = (await db.execute(stmt)).scalar_one_or_none()
    if last_release is not None and last_release.pubkey != pubkey_bytes:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="username_in_cooldown",
        )

    if user.username is not None and user.username != username:
        db.add(UsernameHistory(
            username=user.username,
            pubkey=pubkey_bytes,
            claimed_at=user.created_at,
            released_at=now,
        ))

    user.username = username
    await db.flush()

    return MeInfo(
        pubkey_hex=current.pubkey_hex,
        username=user.username,
        home_relay=user.home_relay,
        tier=user.tier.value,
        created_at=user.created_at,
    )


@router.delete(
    "/me/username",
    response_model=UsernameReleaseResponse,
    summary="Release the current user's @username",
)
async def release_username(
    current: CurrentSession,
    db: DBSession,
) -> UsernameReleaseResponse:
    """Release the current @username. Goes into 30-day cooldown."""
    settings = get_settings()
    pubkey_bytes = bytes.fromhex(current.pubkey_hex)
    now = int(time.time())

    user = await _get_or_create_user(db, current.pubkey_hex)

    if user.username is None:
        return UsernameReleaseResponse(released=False, cooldown_until=0)

    db.add(UsernameHistory(
        username=user.username,
        pubkey=pubkey_bytes,
        claimed_at=user.created_at,
        released_at=now,
    ))

    user.username = None
    await db.flush()

    return UsernameReleaseResponse(
        released=True,
        cooldown_until=now + settings.username_cooldown_days * 86400,
    )


@router.get(
    "/lookup/{username}",
    response_model=UserInfo,
    summary="Find a user by @username — with optional federation fallback",
)
async def lookup_username(
    username: str,
    db: DBSession,
    relay: str | None = None,
) -> UserInfo:
    """
    Public lookup — no auth required.

    Resolution order:
      1. Local lookup by username (always tried first).
      2. If not found locally AND ?relay=hostname is provided AND it isn't
         this relay, perform a federation lookup against that hostname.
         On success, cache the result as a local User row with
         home_relay = <remote>.
      3. Otherwise 404.

    The cache means subsequent send_envelope calls can route correctly
    without re-querying the remote relay every time.
    """
    settings = get_settings()
    normalized = normalize_username(username)

    # 1. Local lookup
    stmt = (
        select(User)
        .where(User.username == normalized)
        .where(User.deleted_at.is_(None))
    )
    user = (await db.execute(stmt)).scalar_one_or_none()
    if user is not None:
        return UserInfo(
            pubkey_hex=user.pubkey.hex(),
            username=user.username,
            home_relay=user.home_relay,
            last_seen_at=user.last_seen_at,
        )

    # 2. Federation fallback only if caller hints which relay
    if relay is not None and relay != settings.relay_name:
        logger.info("Federation lookup: %s on %s", normalized, relay)
        result = await remote_lookup(relay, normalized)
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="username_not_found_on_remote_relay",
            )

        # Cache locally for future send_envelope routing
        cached = await _cache_remote_user(
            db,
            pubkey_hex=result["pubkey_hex"],
            username=result["username"],
            home_relay=result["home_relay"],
        )

        return UserInfo(
            pubkey_hex=result["pubkey_hex"],
            username=result["username"],
            home_relay=result["home_relay"],
            last_seen_at=cached.last_seen_at if cached else None,
        )

    # 3. Nothing found, no relay hint
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="username_not_found",
    )
