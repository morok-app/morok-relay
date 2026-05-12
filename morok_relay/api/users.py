"""
User and username endpoints.

GET    /api/v1/users/me                    — get my profile
POST   /api/v1/users/me/username           — claim a @username
DELETE /api/v1/users/me/username           — release my @username
GET    /api/v1/users/lookup/{username}     — find user by @username (public)

Username rules
--------------
- 3-20 chars, lowercase letters/digits/underscores
- Must not start with digit or underscore
- Cannot be in RESERVED_USERNAMES
- After release, the name enters a cooldown (MOROK_USERNAME_COOLDOWN_DAYS, default 30)
  during which only the original owner can re-claim it. Different pubkey must wait.

This prevents impersonation by squatting on a recently-released handle.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from ..config import get_settings
from ..deps import CurrentSession, DBSession
from ..models import User, UsernameHistory
from ..schemas import (
    MeInfo,
    UserInfo,
    UsernameClaim,
    UsernameReleaseResponse,
    normalize_username,
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
    authenticated request.

    Why lazy creation? Auth happens against just a pubkey — we don't require
    "signup" as a separate step. The first time someone authenticates, we
    create their User row. The pubkey alone is their identity; everything
    else (username, etc) is optional metadata added later.
    """
    settings = get_settings()
    pubkey_bytes = bytes.fromhex(pubkey_hex)

    stmt = select(User).where(User.pubkey == pubkey_bytes)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is not None:
        # Touch last_seen — best-effort, no error if it conflicts.
        user.last_seen_at = int(time.time())
        return user

    user = User(
        pubkey=pubkey_bytes,
        home_relay=settings.relay_name,
        last_seen_at=int(time.time()),
    )
    db.add(user)
    await db.flush()  # need the row visible before subsequent queries in same txn
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
    Reserve a @username. The name is normalized (lowercased, @-stripped) and
    validated by UsernameClaim.

    Errors:
    - 409 conflict: name currently belongs to someone else
    - 409 conflict: name is in cooldown after recent release by a different pubkey
    - 400: validation fails (handled by Pydantic before reaching this handler)
    """
    settings = get_settings()
    username = normalize_username(body.username)
    pubkey_bytes = bytes.fromhex(current.pubkey_hex)
    now = int(time.time())

    user = await _get_or_create_user(db, current.pubkey_hex)

    # If the caller already owns this name — no-op, idempotent.
    if user.username == username:
        return MeInfo(
            pubkey_hex=current.pubkey_hex,
            username=user.username,
            home_relay=user.home_relay,
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

    # Is the name in cooldown after a recent release? Only blocks if the
    # most-recent releaser was a DIFFERENT pubkey from the current one.
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

    # If the user already has a different username, that one needs to be
    # released first. We do this implicitly: record it in history before
    # overwriting.
    if user.username is not None and user.username != username:
        history = UsernameHistory(
            username=user.username,
            pubkey=pubkey_bytes,
            claimed_at=user.created_at,  # best-effort approximation
            released_at=now,
        )
        db.add(history)

    user.username = username
    await db.flush()

    return MeInfo(
        pubkey_hex=current.pubkey_hex,
        username=user.username,
        home_relay=user.home_relay,
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
    """
    Release the current @username. Goes into cooldown — only this pubkey can
    re-claim it within the cooldown window.
    """
    settings = get_settings()
    pubkey_bytes = bytes.fromhex(current.pubkey_hex)
    now = int(time.time())

    user = await _get_or_create_user(db, current.pubkey_hex)

    if user.username is None:
        return UsernameReleaseResponse(released=False, cooldown_until=0)

    released_name = user.username
    history = UsernameHistory(
        username=released_name,
        pubkey=pubkey_bytes,
        claimed_at=user.created_at,
        released_at=now,
    )
    db.add(history)

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
    """
    Public lookup — no auth required. Returns minimal info needed to start
    a chat with this user (their pubkey and home_relay).

    404 if the username is not claimed by anyone.
    """
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
