"""
Dead Man's Switch endpoints.

Rate limit: POST /api/v1/dms is limited to 5/min per pubkey because each
DMS row carries up to 256 KB payload — limiting creates prevents abuse.
GET/check-in/cancel are not limited (single-row reads or status flips).
"""
from __future__ import annotations

import base64
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from ..config import get_settings
from ..deps import CurrentSession, DBSession
from ..models import DeadManSwitch, DMSRecipient, DMSStatus, User, UserTier
from ..rate_limit import rate_limit_by_pubkey
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


async def _get_current_user(db, pubkey_hex: str) -> User:
    pubkey = bytes.fromhex(pubkey_hex)
    stmt = select(User).where(User.pubkey == pubkey)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if user is None:
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
    stmt = (
        select(DeadManSwitch)
        .where(DeadManSwitch.id == dms_id)
        .options(selectinload(DeadManSwitch.recipients))
    )
    dms = (await db.execute(stmt)).scalar_one_or_none()
    if dms is None or dms.creator_pubkey != owner_pubkey:
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


@router.post(
    "",
    response_model=DMSInfo,
    status_code=status.HTTP_201_CREATED,
    summary="Create a Dead Man's Switch",
    dependencies=[Depends(rate_limit_by_pubkey(
        "dms_create",
        get_settings().rate_limit_dms_create_per_minute,
    ))],
)
async def create_dms(
    body: DMSCreate,
    current: CurrentSession,
    db: DBSession,
) -> DMSInfo:
    user = await _get_current_user(db, current.pubkey_hex)
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


@router.get("", response_model=list[DMSInfo])
async def list_my_dms(
    current: CurrentSession, db: DBSession,
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


@router.get("/{dms_id}", response_model=DMSInfo)
async def get_dms(
    dms_id: str, current: CurrentSession, db: DBSession,
) -> DMSInfo:
    did = _parse_dms_id(dms_id)
    pubkey = bytes.fromhex(current.pubkey_hex)
    dms = await _load_dms_for_owner(db, did, pubkey)
    return _to_info(dms)


@router.post("/{dms_id}/check-in", response_model=DMSCheckInResponse)
async def check_in(
    dms_id: str, current: CurrentSession, db: DBSession,
) -> DMSCheckInResponse:
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


@router.delete("/{dms_id}", response_model=DMSCancelResponse)
async def cancel_dms(
    dms_id: str, current: CurrentSession, db: DBSession,
) -> DMSCancelResponse:
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


async def bump_check_in_for_pubkey(db, pubkey_hex: str) -> int:
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
