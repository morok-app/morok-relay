"""
Group and channel endpoints.

Rate limits:
- POST /api/v1/groups               — 5/min per pubkey (creates new group)
- POST /api/v1/groups/{id}/messages — 30/min per pubkey (broadcasts to N)
- POST /api/v1/groups/{id}/invites  — 10/min per pubkey (create invite tokens)
- POST /api/v1/groups/join          — 5/min per pubkey (anti-abuse on token guess)
Other endpoints are not rate-limited at this layer (no DB writes or only
single-row updates).
"""
from __future__ import annotations

import base64
import logging
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from .. import blob_storage, crypto, invite_tokens
from ..config import get_settings
from ..deps import CurrentSession, DBSession, RedisClient
from ..models import Group, GroupMember, User, UserTier
from ..queue import enqueue_envelope_for_recipients, envelope_exists
from ..rate_limit import rate_limit_by_pubkey
from ..schemas import (
    GroupAddMemberRequest,
    GroupCreate,
    GroupEnvelopeAck,
    GroupEnvelopeIn,
    GroupInfo,
    GroupInfoDetailed,
    GroupMemberInfo,
    GroupMembershipChange,
    InviteTokenCreate,
    InviteTokenInfo,
    InviteTokenList,
    JoinViaTokenResponse,
    INVITE_TOKEN_PATTERN,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["groups"])

FREE_TIER_MAX_MEMBERS = 50
PREMIUM_TIER_MAX_MEMBERS = 200


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


def _parse_group_id(group_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(group_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_group_id",
        )


async def _load_group(db, group_id: uuid.UUID) -> Group:
    stmt = (
        select(Group)
        .where(Group.id == group_id)
        .where(Group.deleted_at.is_(None))
        .options(selectinload(Group.members))
    )
    group = (await db.execute(stmt)).scalar_one_or_none()
    if group is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="group_not_found",
        )
    return group


def _is_member(group: Group, pubkey: bytes) -> bool:
    return any(m.pubkey == pubkey for m in group.members)


def _find_admin(group: Group) -> GroupMember | None:
    for m in group.members:
        if m.is_admin:
            return m
    return None


def _to_group_info(group: Group) -> GroupInfo:
    return GroupInfo(
        group_id=str(group.id),
        creator_pubkey_hex=group.creator_pubkey.hex(),
        name_encrypted=base64.b64encode(group.name_encrypted).decode(),
        is_channel=group.is_channel,
        default_ttl_seconds=group.default_ttl_seconds,
        anonymous_senders=group.anonymous_senders,
        expires_at=group.expires_at,
        slug=group.slug,
        max_members=group.max_members,
        created_at=group.created_at,
        member_count=len(group.members),
    )


def _to_group_info_detailed(group: Group) -> GroupInfoDetailed:
    base = _to_group_info(group)
    return GroupInfoDetailed(
        **base.model_dump(),
        members=[
            GroupMemberInfo(
                pubkey_hex=m.pubkey.hex(),
                is_admin=m.is_admin,
                joined_at=m.joined_at,
            )
            for m in group.members
        ],
    )


@router.post(
    "",
    response_model=GroupInfoDetailed,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new group or channel",
    dependencies=[Depends(rate_limit_by_pubkey(
        "groups_create",
        get_settings().rate_limit_group_create_per_minute,
    ))],
)
async def create_group(
    body: GroupCreate,
    current: CurrentSession,
    db: DBSession,
) -> GroupInfoDetailed:
    user = await _get_current_user(db, current.pubkey_hex)
    now = int(time.time())

    if user.tier == UserTier.PREMIUM or user.tier == UserTier.ADMIN:
        max_members = PREMIUM_TIER_MAX_MEMBERS
    else:
        max_members = FREE_TIER_MAX_MEMBERS

    if body.slug is not None and user.tier == UserTier.FREE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="slug_requires_premium",
        )

    if body.slug is not None:
        stmt = select(Group).where(
            Group.slug == body.slug,
            Group.deleted_at.is_(None),
        )
        existing = (await db.execute(stmt)).scalar_one_or_none()
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="slug_taken",
            )

    if body.expires_at is not None:
        if body.expires_at <= now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="expires_at_must_be_in_future",
            )
        if body.expires_at > now + 365 * 86400:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="expires_at_too_far_in_future",
            )

    name_bytes = base64.b64decode(body.name_encrypted, validate=True)
    creator_pubkey = bytes.fromhex(current.pubkey_hex)

    group = Group(
        creator_pubkey=creator_pubkey,
        name_encrypted=name_bytes,
        is_channel=body.is_channel,
        default_ttl_seconds=body.default_ttl_seconds,
        slug=body.slug,
        expires_at=body.expires_at,
        anonymous_senders=body.anonymous_senders,
        max_members=max_members,
    )
    db.add(group)
    await db.flush()

    db.add(GroupMember(
        group_id=group.id,
        pubkey=creator_pubkey,
        is_admin=True,
        joined_at=now,
    ))
    await db.flush()
    await db.refresh(group, attribute_names=["members"])

    return _to_group_info_detailed(group)


@router.get("", response_model=list[GroupInfo])
async def list_my_groups(current: CurrentSession, db: DBSession) -> list[GroupInfo]:
    pubkey = bytes.fromhex(current.pubkey_hex)
    stmt = (
        select(Group)
        .join(GroupMember, GroupMember.group_id == Group.id)
        .where(GroupMember.pubkey == pubkey)
        .where(Group.deleted_at.is_(None))
        .options(selectinload(Group.members))
        .order_by(Group.created_at.desc())
    )
    groups = (await db.execute(stmt)).scalars().all()
    return [_to_group_info(g) for g in groups]


@router.get("/{group_id}", response_model=GroupInfoDetailed)
async def get_group(
    group_id: str, current: CurrentSession, db: DBSession,
) -> GroupInfoDetailed:
    gid = _parse_group_id(group_id)
    group = await _load_group(db, gid)
    pubkey = bytes.fromhex(current.pubkey_hex)
    if not _is_member(group, pubkey):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="not_a_member",
        )
    return _to_group_info_detailed(group)


@router.delete("/{group_id}")
async def delete_group(
    group_id: str, current: CurrentSession, db: DBSession,
) -> dict:
    gid = _parse_group_id(group_id)
    group = await _load_group(db, gid)
    pubkey = bytes.fromhex(current.pubkey_hex)
    if group.creator_pubkey != pubkey:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="only_creator_can_delete",
        )
    group.deleted_at = int(time.time())
    return {"deleted": True, "group_id": str(group.id)}


@router.post("/{group_id}/members", response_model=GroupMembershipChange)
async def add_member(
    group_id: str, body: GroupAddMemberRequest,
    current: CurrentSession, db: DBSession,
) -> GroupMembershipChange:
    gid = _parse_group_id(group_id)
    group = await _load_group(db, gid)
    caller = bytes.fromhex(current.pubkey_hex)
    admin_member = _find_admin(group)
    if admin_member is None or admin_member.pubkey != caller:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="only_admin_can_add_members",
        )
    new_member_pubkey = bytes.fromhex(body.pubkey_hex)
    if _is_member(group, new_member_pubkey):
        return GroupMembershipChange(
            group_id=str(group.id),
            member_pubkey_hex=body.pubkey_hex,
            action="added",
            member_count=len(group.members),
        )
    if len(group.members) >= group.max_members:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"group_full_max_{group.max_members}_members",
        )
    db.add(GroupMember(
        group_id=group.id,
        pubkey=new_member_pubkey,
        is_admin=False,
        joined_at=int(time.time()),
    ))
    await db.flush()
    await db.refresh(group, attribute_names=["members"])
    return GroupMembershipChange(
        group_id=str(group.id),
        member_pubkey_hex=body.pubkey_hex,
        action="added",
        member_count=len(group.members),
    )


@router.delete(
    "/{group_id}/members/{pubkey_hex}",
    response_model=GroupMembershipChange,
)
async def remove_member(
    group_id: str, pubkey_hex: str,
    current: CurrentSession, db: DBSession,
) -> GroupMembershipChange:
    gid = _parse_group_id(group_id)
    group = await _load_group(db, gid)
    if len(pubkey_hex) != 64 or not all(c in "0123456789abcdef" for c in pubkey_hex):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_pubkey",
        )
    caller = bytes.fromhex(current.pubkey_hex)
    target = bytes.fromhex(pubkey_hex)
    is_self = caller == target
    admin_member = _find_admin(group)
    is_admin = admin_member is not None and admin_member.pubkey == caller
    if not (is_self or is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="must_be_self_or_admin",
        )
    if target == group.creator_pubkey:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="creator_cannot_leave_must_delete_group",
        )
    target_member = next((m for m in group.members if m.pubkey == target), None)
    if target_member is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="not_a_member",
        )
    await db.delete(target_member)
    await db.flush()
    await db.refresh(group, attribute_names=["members"])
    return GroupMembershipChange(
        group_id=str(group.id),
        member_pubkey_hex=pubkey_hex,
        action="removed",
        member_count=len(group.members),
    )


@router.get("/by-slug/{slug}", response_model=GroupInfo)
async def lookup_by_slug(slug: str, db: DBSession) -> GroupInfo:
    from ..schemas import normalize_slug
    normalized = normalize_slug(slug)
    stmt = (
        select(Group)
        .where(Group.slug == normalized)
        .where(Group.deleted_at.is_(None))
        .options(selectinload(Group.members))
    )
    group = (await db.execute(stmt)).scalar_one_or_none()
    if group is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="slug_not_found",
        )
    return _to_group_info(group)


@router.post(
    "/{group_id}/messages",
    response_model=GroupEnvelopeAck,
    summary="Broadcast a message to all members of a group",
    dependencies=[Depends(rate_limit_by_pubkey(
        "groups_message",
        get_settings().rate_limit_group_messages_per_minute,
    ))],
)
async def send_group_message(
    group_id: str,
    body: GroupEnvelopeIn,
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
) -> GroupEnvelopeAck:
    settings = get_settings()
    gid = _parse_group_id(group_id)
    group = await _load_group(db, gid)

    if body.to != str(group.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="envelope_to_must_match_url_group_id",
        )

    if body.from_ != current.pubkey_hex:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="from_field_must_match_authenticated_pubkey",
        )

    sender_pubkey = bytes.fromhex(current.pubkey_hex)
    if not _is_member(group, sender_pubkey):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="not_a_member",
        )

    if group.is_channel:
        admin_member = _find_admin(group)
        if admin_member is None or admin_member.pubkey != sender_pubkey:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="channel_admin_only_post",
            )

    unsigned = {
        "from": body.from_, "to": body.to,
        "ts": body.ts, "ttl": body.ttl, "blob": body.blob,
    }
    canonical = crypto.canonical_json(unsigned)
    try:
        sig_bytes = bytes.fromhex(body.sig)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_sig_hex",
        )
    if not crypto.ed25519_verify(canonical, sig_bytes, sender_pubkey):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="signature_invalid",
        )

    now = int(time.time())
    if body.ts < now - 300:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="envelope_too_old",
        )
    if body.ts > now + 60:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="envelope_from_the_future",
        )

    try:
        blob_bytes = base64.b64decode(body.blob, validate=True)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="blob_not_base64",
        )
    if len(blob_bytes) > settings.max_blob_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"blob_too_large_max_{settings.max_blob_bytes}_bytes",
        )

    import hashlib
    h = hashlib.sha256()
    h.update(sender_pubkey)
    h.update(group.id.bytes)
    h.update(body.ts.to_bytes(8, "big"))
    h.update(hashlib.sha256(blob_bytes).digest())
    envelope_id = h.hexdigest()

    if await envelope_exists(redis, envelope_id):
        return GroupEnvelopeAck(
            envelope_id=envelope_id,
            queued=False,
            recipient_count=0,
            expires_at=0,
        )

    # Snapshot sender username for the recipient client UI
    sender_stmt = (
        select(User)
        .where(User.pubkey == sender_pubkey)
        .where(User.deleted_at.is_(None))
    )
    sender_user = (await db.execute(sender_stmt)).scalar_one_or_none()
    sender_username = (
        sender_user.username
        if sender_user and not group.anonymous_senders
        else None
    )

    await blob_storage.write_blob(envelope_id, blob_bytes)
    recipient_pubkeys = [m.pubkey.hex() for m in group.members]
    expires_at, recipient_count = await enqueue_envelope_for_recipients(
        redis=redis,
        envelope_id=envelope_id,
        sender_pubkey_hex=body.from_,
        recipient_pubkeys_hex=recipient_pubkeys,
        timestamp=body.ts,
        ttl_seconds=body.ttl,
        signature_hex=body.sig,
        hard_ceiling_seconds=settings.message_ttl_hard_seconds,
        group_id=str(group.id),
        sender_username=sender_username,
    )
    return GroupEnvelopeAck(
        envelope_id=envelope_id,
        queued=True,
        recipient_count=recipient_count,
        expires_at=expires_at,
    )


# ============================================================================
# INVITE TOKENS (Day 6 — variant B)
# ============================================================================

@router.post(
    "/{group_id}/invites",
    response_model=InviteTokenInfo,
    status_code=status.HTTP_201_CREATED,
    summary="Admin creates a one-time invite token for the group",
    dependencies=[Depends(rate_limit_by_pubkey(
        "group_invite_create",
        10,
    ))],
)
async def create_invite_token(
    group_id: str,
    body: InviteTokenCreate,
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
) -> InviteTokenInfo:
    gid = _parse_group_id(group_id)
    group = await _load_group(db, gid)
    caller = bytes.fromhex(current.pubkey_hex)
    admin_member = _find_admin(group)
    if admin_member is None or admin_member.pubkey != caller:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="only_admin_can_create_invites",
        )

    active = await invite_tokens.count_active_tokens(redis, str(group.id))
    if active >= invite_tokens.MAX_ACTIVE_TOKENS_PER_GROUP:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"too_many_active_invites_max_{invite_tokens.MAX_ACTIVE_TOKENS_PER_GROUP}",
        )

    ttl = body.ttl_seconds or invite_tokens.DEFAULT_TTL_SECONDS
    info = await invite_tokens.create_token(
        redis=redis,
        group_id=str(group.id),
        created_by_pubkey_hex=current.pubkey_hex,
        ttl_seconds=ttl,
    )
    return InviteTokenInfo(
        token=info["token"],
        group_id=str(group.id),
        created_by_pubkey_hex=current.pubkey_hex,
        created_at=info["created_at"],
        expires_at=info["expires_at"],
    )


@router.get(
    "/{group_id}/invites",
    response_model=InviteTokenList,
    summary="List active invite tokens for a group (admin only)",
)
async def list_invite_tokens(
    group_id: str,
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
) -> InviteTokenList:
    gid = _parse_group_id(group_id)
    group = await _load_group(db, gid)
    caller = bytes.fromhex(current.pubkey_hex)
    admin_member = _find_admin(group)
    if admin_member is None or admin_member.pubkey != caller:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="only_admin_can_list_invites",
        )

    raw_tokens = await invite_tokens.list_tokens(redis, str(group.id))
    tokens = [
        InviteTokenInfo(
            token=t["token"],
            group_id=t["group_id"],
            created_by_pubkey_hex=t["created_by"],
            created_at=t["created_at"],
            expires_at=t["expires_at"],
        )
        for t in raw_tokens
    ]
    return InviteTokenList(tokens=tokens)


@router.delete(
    "/{group_id}/invites/{token}",
    summary="Revoke an invite token",
)
async def revoke_invite_token(
    group_id: str,
    token: str,
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
) -> dict:
    if not INVITE_TOKEN_PATTERN.match(token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_token",
        )
    gid = _parse_group_id(group_id)
    group = await _load_group(db, gid)
    caller = bytes.fromhex(current.pubkey_hex)
    admin_member = _find_admin(group)
    if admin_member is None or admin_member.pubkey != caller:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="only_admin_can_revoke_invites",
        )
    revoked = await invite_tokens.revoke_token(redis, str(group.id), token)
    return {"revoked": revoked}


@router.post(
    "/join",
    response_model=JoinViaTokenResponse,
    summary="Join a group via invite token (one-time-use)",
    dependencies=[Depends(rate_limit_by_pubkey(
        "group_join_via_token",
        5,
    ))],
)
async def join_via_token(
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
    token: str = Query(..., min_length=20, max_length=40),
) -> JoinViaTokenResponse:
    """
    Public endpoint (requires session, but caller doesn't need to be a
    member or admin of the group). Consumes the token, adds the caller as
    a regular (non-admin) member, and returns the group's id + new size.
    """
    if not INVITE_TOKEN_PATTERN.match(token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_token",
        )

    meta = await invite_tokens.consume_token(redis, token)
    if meta is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="invite_token_invalid_or_expired",
        )

    group_id_str = meta["group_id"]
    gid = _parse_group_id(group_id_str)
    group = await _load_group(db, gid)

    caller = bytes.fromhex(current.pubkey_hex)

    # Already a member? — just return success
    if _is_member(group, caller):
        return JoinViaTokenResponse(
            group_id=group_id_str,
            joined=True,
            member_count=len(group.members),
        )

    if len(group.members) >= group.max_members:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"group_full_max_{group.max_members}_members",
        )

    db.add(GroupMember(
        group_id=group.id,
        pubkey=caller,
        is_admin=False,
        joined_at=int(time.time()),
    ))
    await db.flush()
    await db.refresh(group, attribute_names=["members"])

    logger.info(
        "User %s... joined group %s via invite token",
        current.pubkey_hex[:8], group_id_str,
    )

    return JoinViaTokenResponse(
        group_id=group_id_str,
        joined=True,
        member_count=len(group.members),
    )
