"""
Dead Man's Switch endpoints.

POST   /api/v1/dms                — create a DMS
GET    /api/v1/dms                — list my DMS
GET    /api/v1/dms/{dms_id}       — DMS details
DELETE /api/v1/dms/{dms_id}       — cancel and delete a DMS
POST   /api/v1/dms/{dms_id}/check-in — explicit check-in (also: any auth request)

How it works
------------
- User creates DMS with an encrypted payload + recipients + trigger_seconds.
- last_check_in_at is set to "now" on creation.
- Every authenticated request from the owner bumps last_check_in_at (via
  the get_current_session dependency).
- The DMS reaper runs hourly. Any 'armed' switch where
  (now - last_check_in_at) > trigger_seconds gets fired.
- Firing = for each recipient, create a regular envelope with the payload
  and queue it for delivery via the normal message pipeline.
- After firing, status -> triggered.
- Owner can cancel a DMS anytime to prevent it firing.

Tier limits
-----------
- Free:    up to 5 recipients per DMS
- Premium: up to 20 recipients per DMS

No hard limit on number of switches per user, but each costs a row in the DB
and storage for the encrypted payload (up to 256 KB each).
"""
from __future__ import annotations

import time
import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from ..deps import CurrentSession, DBSession
from ..models import DeadManSwitch, DMSRecipient, DMSStatus, User, UserTier
from ..schemas import (
    DMS_FREE_TIER_MAX_RECIPIENTS,
    DMS_PREMIUM_TIER_MAX_RECIPIENTS,
    DMSCancelResponse,
    DMSCheckInResponse,
    DMSCreate,
    DMSInfo,
    DMSRecipientInfo,
)

router = APIRouter(tags=["dms"])


# ============================================================================
# Helpers
# ============================================================================

import base64


async def _get_current_user(db, pubkey_hex: str) -> User:
    pubkey = bytes.fromhex(pubkey_hex)
    stmt = select(User).where(User.pubkey == pubkey)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if user is None:
        from ..config import get_settings
        settings = get_settings()
        user = User(
            pubkey=pubkey,
            home_relay=settings.relay_name,
            tier=UserTier.FREE,
            last_seen_at=int(time.time()),
        )
        db.add(user)
        await db.flush()
    return user


def _parse_dms_id(dms_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(dms_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_dms_id",
        )


async def _load_dms_for_owner(db, dms_id: uuid.UUID, owner_pubkey: bytes) -> DeadManSwitch:
    """Load a DMS, ensuring the caller is its owner."""
    stmt = (
        select(DeadManSwitch)
        .where(DeadManSwitch.id == dms_id)
        .options(selectinload(DeadManSwitch.recipients))
    )
    dms = (await db.execute(stmt)).scalar_one_or_none()

    if dms is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="dms_not_found",
        )
    if dms.creator_pubkey != owner_pubkey:
        # Don't leak existence — same code as not found
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="dms_not_found",
        )
    return dms


def _to_info(dms: DeadManSwitch) -> DMSInfo:
    return DMSInfo(
        dms_id=str(dms.id),
        trigger_seconds=dms.trigger_seconds,
        last_check_in_at=dms.last_check_in_at,
        fires_at=dms.last_check_in_at + dms.trigger_seconds,
        label=dms.label,
        status=dms.status.value,
        created_at=dms.created_at,
        triggered_at=dms.triggered_at,
        cancelled_at=dms.cancelled_at,
        recipients=[
            DMSRecipientInfo(
                recipient_pubkey_hex=r.recipient_pubkey.hex(),
                delivered_at=r.delivered_at,
            )
            for r in dms.recipients
        ],
    )


# ============================================================================
# Endpoints
# ============================================================================

@router.post(
    "",
    response_model=DMSInfo,
    status_code=status.HTTP_201_CREATED,
    summary="Create a Dead Man's Switch",
)
async def create_dms(
    body: DMSCreate,
    current: CurrentSession,
    db: DBSession,
) -> DMSInfo:
    """
    Create a new Dead Man's Switch. Recipient count is gated by tier.
    """
    user = await _get_current_user(db, current.pubkey_hex)

    # Tier-based recipient limit
    if user.tier == UserTier.PREMIUM or user.tier == UserTier.ADMIN:
        max_recipients = DMS_PREMIUM_TIER_MAX_RECIPIENTS
    else:
        max_recipients = DMS_FREE_TIER_MAX_RECIPIENTS

    if len(body.recipient_pubkeys_hex) > max_recipients:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"too_many_recipients_for_tier_max_{max_recipients}",
        )

    creator_pubkey = bytes.fromhex(current.pubkey_hex)
    now = int(time.time())
    payload_bytes = base64.b64decode(body.payload_encrypted, validate=True)

    dms = DeadManSwitch(
        creator_pubkey=creator_pubkey,
        trigger_seconds=body.trigger_seconds,
        last_check_in_at=now,
        payload_encrypted=payload_bytes,
        label=body.label,
        status=DMSStatus.ARMED,
    )
    db.add(dms)
    await db.flush()

    for pk_hex in body.recipient_pubkeys_hex:
        db.add(DMSRecipient(
            dms_id=dms.id,
            recipient_pubkey=bytes.fromhex(pk_hex),
        ))
    await db.flush()
    await db.refresh(dms, attribute_names=["recipients"])

    return _to_info(dms)


@router.get(
    "",
    response_model=list[DMSInfo],
    summary="List all my DMS",
)
async def list_my_dms(
    current: CurrentSession,
    db: DBSession,
) -> list[DMSInfo]:
    pubkey = bytes.fromhex(current.pubkey_hex)
    stmt = (
        select(DeadManSwitch)
        .where(DeadManSwitch.creator_pubkey == pubkey)
        .options(selectinload(DeadManSwitch.recipients))
        .order_by(DeadManSwitch.created_at.desc())
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_info(d) for d in rows]


@router.get(
    "/{dms_id}",
    response_model=DMSInfo,
    summary="Get DMS details",
)
async def get_dms(
    dms_id: str,
    current: CurrentSession,
    db: DBSession,
) -> DMSInfo:
    did = _parse_dms_id(dms_id)
    pubkey = bytes.fromhex(current.pubkey_hex)
    dms = await _load_dms_for_owner(db, did, pubkey)
    return _to_info(dms)


@router.post(
    "/{dms_id}/check-in",
    response_model=DMSCheckInResponse,
    summary="Explicitly bump last_check_in_at to delay trigger",
)
async def check_in(
    dms_id: str,
    current: CurrentSession,
    db: DBSession,
) -> DMSCheckInResponse:
    """
    Explicit check-in. Any authenticated request also bumps last_check_in_at
    via the session dependency, but this endpoint lets the client perform a
    no-op "I'm still here" without other side effects.

    Only works on 'armed' switches — triggered/cancelled returns 409.
    """
    did = _parse_dms_id(dms_id)
    pubkey = bytes.fromhex(current.pubkey_hex)
    dms = await _load_dms_for_owner(db, did, pubkey)

    if dms.status != DMSStatus.ARMED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"dms_not_armed_status_{dms.status.value}",
        )

    now = int(time.time())
    dms.last_check_in_at = now
    await db.flush()

    return DMSCheckInResponse(
        dms_id=str(dms.id),
        last_check_in_at=now,
        fires_at=now + dms.trigger_seconds,
    )


@router.delete(
    "/{dms_id}",
    response_model=DMSCancelResponse,
    summary="Cancel and delete a DMS",
)
async def cancel_dms(
    dms_id: str,
    current: CurrentSession,
    db: DBSession,
) -> DMSCancelResponse:
    """
    Cancel a DMS. If 'armed', it transitions to 'cancelled' (preserving
    history). If already triggered, this is a no-op that returns
    cancelled=False (because firing already happened).

    The row is kept for audit. Hard deletion happens via a future cleanup
    job (or the user can re-create with same recipients/payload).
    """
    did = _parse_dms_id(dms_id)
    pubkey = bytes.fromhex(current.pubkey_hex)
    dms = await _load_dms_for_owner(db, did, pubkey)

    if dms.status == DMSStatus.TRIGGERED:
        return DMSCancelResponse(dms_id=str(dms.id), cancelled=False)

    if dms.status == DMSStatus.CANCELLED:
        return DMSCancelResponse(dms_id=str(dms.id), cancelled=True)

    dms.status = DMSStatus.CANCELLED
    dms.cancelled_at = int(time.time())
    await db.flush()

    return DMSCancelResponse(dms_id=str(dms.id), cancelled=True)


# ============================================================================
# Helper for other code (used by deps.py to bump check-in on auth)
# ============================================================================

async def bump_check_in_for_pubkey(db, pubkey_hex: str) -> int:
    """
    Update last_check_in_at for all of this user's armed DMS to now.

    Called from the session dependency on every authenticated request.
    Returns the number of switches updated (for logging — 0 is fine).

    Cheap: a single UPDATE with index on (creator_pubkey, status).
    """
    pubkey = bytes.fromhex(pubkey_hex)
    now = int(time.time())
    stmt = (
        update(DeadManSwitch)
        .where(
            DeadManSwitch.creator_pubkey == pubkey,
            DeadManSwitch.status == DMSStatus.ARMED,
        )
        .values(last_check_in_at=now)
    )
    result = await db.execute(stmt)
    return result.rowcount or 0
