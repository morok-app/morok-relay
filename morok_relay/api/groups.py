"""
Group and channel endpoints.

POST    /api/v1/groups                                   — create group/channel
GET     /api/v1/groups                                   — list groups I'm a member of
GET     /api/v1/groups/{group_id}                        — full details + members
DELETE  /api/v1/groups/{group_id}                        — delete (creator only)
POST    /api/v1/groups/{group_id}/members                — admin adds a member
DELETE  /api/v1/groups/{group_id}/members/{pubkey_hex}   — leave self or admin kicks
GET     /api/v1/groups/by-slug/{slug}                    — public lookup for channels
POST    /api/v1/groups/{group_id}/messages               — broadcast message to group

Tier limits
-----------
- Free creator:    50 members max, slug not allowed
- Premium creator: 200 members max, slug allowed

Admin model in v1
-----------------
Creator is the sole admin. No way to promote/demote yet.

Channels (is_channel=True)
--------------------------
Only the admin can post messages. Members can read.

Anonymous senders
-----------------
If anonymous_senders=True, the relay still sees who sent each message
(it verifies the signature). Clients SHOULD render anonymous-group
messages as from the group itself. This is "anonymity toward other
members", not "toward the relay". v2 will add ring signatures for the
latter.
"""
from __future__ import annotations

import base64
import time
import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from .. import blob_storage, crypto
from ..config import get_settings
from ..deps import CurrentSession, DBSession, RedisClient
from ..models import Group, GroupMember, User, UserTier
from ..queue import enqueue_envelope_for_recipients, envelope_exists
from ..schemas import (
    GroupAddMemberRequest,
    GroupCreate,
    GroupEnvelopeAck,
    GroupEnvelopeIn,
    GroupInfo,
    GroupInfoDetailed,
    GroupMemberInfo,
    GroupMembershipChange,
)

router = APIRouter(tags=["groups"])

FREE_TIER_MAX_MEMBERS = 50
PREMIUM_TIER_MAX_MEMBERS = 200


# ============================================================================
# Helpers
# ============================================================================

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


# ============================================================================
# Endpoints
# ============================================================================

@router.post(
    "",
    response_model=GroupInfoDetailed,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new group or channel",
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


@router.get(
    "",
    response_model=list[GroupInfo],
    summary="List groups I'm a member of",
)
async def list_my_groups(
    current: CurrentSession,
    db: DBSession,
) -> list[GroupInfo]:
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


@router.get(
    "/{group_id}",
    response_model=GroupInfoDetailed,
    summary="Get group details including member list",
)
async def get_group(
    group_id: str,
    current: CurrentSession,
    db: DBSession,
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


@router.delete(
    "/{group_id}",
    summary="Delete a group (creator only)",
)
async def delete_group(
    group_id: str,
    current: CurrentSession,
    db: DBSession,
) -> dict:
    """
    Soft-deletes the group. Reaper cleans up messages and the row later.

    Returns {"deleted": true, "group_id": ...}.
    (Not 204 because FastAPI doesn't allow a body with 204.)
    """
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


@router.post(
    "/{group_id}/members",
    response_model=GroupMembershipChange,
    summary="Admin adds a member to the group",
)
async def add_member(
    group_id: str,
    body: GroupAddMemberRequest,
    current: CurrentSession,
    db: DBSession,
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
    summary="Leave a group, or admin kicks a member",
)
async def remove_member(
    group_id: str,
    pubkey_hex: str,
    current: CurrentSession,
    db: DBSession,
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


@router.get(
    "/by-slug/{slug}",
    response_model=GroupInfo,
    summary="Public lookup of a channel by its slug",
)
async def lookup_by_slug(
    slug: str,
    db: DBSession,
) -> GroupInfo:
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


# ============================================================================
# GROUP MESSAGING — broadcast to all members
# ============================================================================

@router.post(
    "/{group_id}/messages",
    response_model=GroupEnvelopeAck,
    summary="Broadcast a message to all members of a group",
)
async def send_group_message(
    group_id: str,
    body: GroupEnvelopeIn,
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
) -> GroupEnvelopeAck:
    """
    Send an encrypted envelope to all members of the group.

    Authorization:
    - Caller must be authenticated as body.from_ (sender pubkey check)
    - Caller must be a member of the group
    - If the group is a channel (is_channel=True), only the admin can post
    - body.to must equal the group_id in the URL

    Encryption: the blob is shared (sender-key model), so the same bytes
    are queued in every member's inbox.
    """
    settings = get_settings()
    gid = _parse_group_id(group_id)
    group = await _load_group(db, gid)

    # 1. URL group_id and envelope.to must agree
    if body.to != str(group.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="envelope_to_must_match_url_group_id",
        )

    # 2. Caller must be the sender pubkey in the envelope
    if body.from_ != current.pubkey_hex:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="from_field_must_match_authenticated_pubkey",
        )

    # 3. Caller must be a member
    sender_pubkey = bytes.fromhex(current.pubkey_hex)
    if not _is_member(group, sender_pubkey):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="not_a_member",
        )

    # 4. Channels: only admin can post
    if group.is_channel:
        admin_member = _find_admin(group)
        if admin_member is None or admin_member.pubkey != sender_pubkey:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="channel_admin_only_post",
            )

    # 5. Verify the envelope signature.
    #    Canonical form of envelope (sans 'sig') is what was signed.
    envelope_dict = {
        "from": body.from_,
        "to": body.to,
        "ts": body.ts,
        "ttl": body.ttl,
        "blob": body.blob,
    }
    canonical = crypto.canonical_json({**envelope_dict})
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

    # Time window check (same as 1-on-1)
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

    # 6. Decode blob, enforce size
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

    # 7. Build envelope_id. For groups we hash (sender, group_id, ts, blob_hash)
    # so the same exact message resubmitted is deduplicated.
    import hashlib
    h = hashlib.sha256()
    h.update(sender_pubkey)
    h.update(group.id.bytes)
    h.update(body.ts.to_bytes(8, "big"))
    h.update(hashlib.sha256(blob_bytes).digest())
    envelope_id = h.hexdigest()

    # Dedup
    if await envelope_exists(redis, envelope_id):
        return GroupEnvelopeAck(
            envelope_id=envelope_id,
            queued=False,
            recipient_count=0,
            expires_at=0,
        )

    # 8. Write blob ONCE (shared by all recipients)
    await blob_storage.write_blob(envelope_id, blob_bytes)

    # 9. Fan-out to every group member (including sender — so they see their
    #    own message in their inbox, which lets multi-device clients sync).
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
    )

    return GroupEnvelopeAck(
        envelope_id=envelope_id,
        queued=True,
        recipient_count=recipient_count,
        expires_at=expires_at,
    )
