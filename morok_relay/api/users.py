"""
User and username endpoints.

GET    /api/v1/users/me                    — get my profile
POST   /api/v1/users/me/username           — claim a @username
DELETE /api/v1/users/me/username           — release my @username
GET    /api/v1/users/lookup/{username}     — find user by @username (public)

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

import time

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from ..config import get_settings
from ..deps import CurrentSession, DBSession
from ..models import User, UsernameHistory, UserTier
from ..schemas import (
    MeInfo,
    UserInfo,
    UsernameClaim,
    UsernameReleaseResponse,
    normalize_username,
    validate_username_for_tier,
)

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

    # Re-validate against this user's tier (Pydantic did only tier-agnostic checks).
    try:
        username = validate_username_for_tier(body.username, user.tier.value)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    pubkey_bytes = bytes.fromhex(current.pubkey_hex)
    now = int(time.time())

    # Idempotent: already owns this name.
    if user.username == username:
        return MeInfo(
            pubkey_hex=current.pubkey_hex,
            username=user.username,
            home_relay=user.home_relay,
            tier=user.tier.value,
            created_at=user.created_at,
        )

    # Is the name currently claimed by someone else?
    stmt = select(User).where(User.username == username)
    other = (await db.execute(stmt)).scalar_one_or_none()
    if other is not None and other.pubkey != pubkey_bytes:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="username_taken",
        )

    # Cooldown check — only blocks different pubkey within cooldown window.
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

    # If switching usernames, record the old one in history.
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
    summary="Find a user by @username",
)
async def lookup_username(
    username: str,
    db: DBSession,
) -> UserInfo:
    """Public lookup — no auth required."""
    normalized = normalize_username(username)
    stmt = select(User).where(User.username == normalized).where(User.deleted_at.is_(None))
    user = (await db.execute(stmt)).scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="username_not_found",
        )

    return UserInfo(
        pubkey_hex=user.pubkey.hex(),
        username=user.username,
        home_relay=user.home_relay,
        last_seen_at=user.last_seen_at,
    )
