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
from ..models import FederationOutboundQueue, FedQueueStatus, Group, GroupMember, User, UserTier
from ..queue import (
    delete_envelope_for_group,
    enqueue_envelope_for_recipients,
    envelope_exists,
    get_envelope_meta,
)
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


async def _to_group_info_detailed(group: Group, db) -> GroupInfoDetailed:
    """
    Build the detailed group response, including each member's username
    (looked up from the users table). Members whose pubkey isn't in
    users yet (e.g. an outside relay's user that was added by pubkey
    only) get username=None — clients render them as @anon_<prefix>.
    """
    base = _to_group_info(group)

    # Bulk-lookup usernames for all member pubkeys in one query
    member_pubkeys = [m.pubkey for m in group.members]
    username_by_pubkey: dict[bytes, str | None] = {}
    if member_pubkeys:
        stmt = (
            select(User.pubkey, User.username)
            .where(User.pubkey.in_(member_pubkeys))
            .where(User.deleted_at.is_(None))
        )
        rows = (await db.execute(stmt)).all()
        for pk, uname in rows:
            username_by_pubkey[bytes(pk)] = uname

    return GroupInfoDetailed(
        **base.model_dump(),
        members=[
            GroupMemberInfo(
                pubkey_hex=m.pubkey.hex(),
                username=username_by_pubkey.get(bytes(m.pubkey)),
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
        home_relay=get_settings().relay_name,
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

    return await _to_group_info_detailed(group, db)


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
    return await _to_group_info_detailed(group, db)


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


def _group_home_relay(group: Group) -> str:
    """
    Return the relay that owns this group, falling back to settings if
    the column is NULL (legacy rows pre-migration 007).
    """
    return group.home_relay or get_settings().relay_name


def compute_group_envelope_id(
    sender_pubkey: bytes,
    group_id_bytes: bytes,
    timestamp: int,
    blob_bytes: bytes,
) -> str:
    """
    Deterministic envelope_id for a group message — same calculation in
    send_group_message and the federation /forward handler, so dedup
    works across the federation hop.
    """
    import hashlib
    h = hashlib.sha256()
    h.update(sender_pubkey)
    h.update(group_id_bytes)
    h.update(timestamp.to_bytes(8, "big"))
    h.update(hashlib.sha256(blob_bytes).digest())
    return h.hexdigest()


async def do_group_fanout(
    group: Group,
    envelope: dict,
    envelope_id: str,
    db,
    redis,
) -> tuple[int, int]:
    """
    Host-side fan-out: deliver an envelope to every member.

    Local members → Redis inbox queue (immediate WS push).
    Remote members → federation_outbound_queue row per target relay,
                     with a "deliver" mode payload listing those members.

    Caller must have ALREADY:
      - validated/dedup'd the envelope
      - persisted the blob via blob_storage.write_blob
      - verified that this relay IS the group's home

    Returns (local_count, remote_relay_count) for the ack.
    """
    settings = get_settings()

    sender_pubkey = bytes.fromhex(envelope["from"])
    recipient_pubkeys_bytes = [
        m.pubkey for m in group.members if m.pubkey != sender_pubkey
    ]
    recipient_pubkeys_hex = [p.hex() for p in recipient_pubkeys_bytes]

    home_by_pubkey_hex: dict[str, str | None] = {}
    if recipient_pubkeys_bytes:
        stmt = (
            select(User.pubkey, User.home_relay)
            .where(User.pubkey.in_(recipient_pubkeys_bytes))
            .where(User.deleted_at.is_(None))
        )
        rows = (await db.execute(stmt)).all()
        for pk, hr in rows:
            home_by_pubkey_hex[bytes(pk).hex()] = hr

    local_recipients: list[str] = []
    remote_by_relay: dict[str, list[str]] = {}

    for pk_hex in recipient_pubkeys_hex:
        home = home_by_pubkey_hex.get(pk_hex)
        # Unknown user (no User row) → treat as local. The /users/lookup
        # path is what populates User rows from federation; if we don't
        # have one, we can't route remotely anyway.
        if home is None or home == settings.relay_name:
            local_recipients.append(pk_hex)
        else:
            remote_by_relay.setdefault(home, []).append(pk_hex)

    if local_recipients:
        await enqueue_envelope_for_recipients(
            redis=redis,
            envelope_id=envelope_id,
            sender_pubkey_hex=envelope["from"],
            recipient_pubkeys_hex=local_recipients,
            timestamp=int(envelope["ts"]),
            ttl_seconds=int(envelope["ttl"]),
            signature_hex=envelope["sig"],
            hard_ceiling_seconds=settings.message_ttl_hard_seconds,
            group_id=str(group.id),
            sender_username=envelope.get("from_username"),
        )

    now = int(time.time())
    for target_relay, members_on_relay in remote_by_relay.items():
        deliver_envelope = {
            "from": envelope["from"],
            "to": envelope["to"],
            "ts": int(envelope["ts"]),
            "ttl": int(envelope["ttl"]),
            "blob": envelope["blob"],
            "sig": envelope["sig"],
            "from_username": envelope.get("from_username"),
            "group_id": str(group.id),
            "group_forward_mode": "deliver",
            "deliver_to_pubkeys": members_on_relay,
        }
        dup_stmt = (
            select(FederationOutboundQueue)
            .where(FederationOutboundQueue.envelope_id == envelope_id)
            .where(FederationOutboundQueue.target_relay == target_relay)
            .limit(1)
        )
        existing = (await db.execute(dup_stmt)).scalar_one_or_none()
        if existing is None:
            db.add(FederationOutboundQueue(
                envelope_id=envelope_id,
                envelope_data=deliver_envelope,
                target_relay=target_relay,
                status=FedQueueStatus.PENDING,
                attempts=0,
                next_attempt_at=now,
                created_at=now,
            ))
    if remote_by_relay:
        await db.flush()

    return len(local_recipients), len(remote_by_relay)


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

    import hashlib  # keep import-local for parity with earlier code
    envelope_id = compute_group_envelope_id(
        sender_pubkey, group.id.bytes, body.ts, blob_bytes,
    )

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

    home = _group_home_relay(group)
    expires_at = body.ts + body.ttl
    now = int(time.time())

    # ------------------------------------------------------------------
    # CASE 1: I'm NOT the host → hand off to host via federation.
    # We don't store the blob or enqueue locally — the host will do that.
    # ------------------------------------------------------------------
    if home != settings.relay_name:
        dup_stmt = (
            select(FederationOutboundQueue)
            .where(FederationOutboundQueue.envelope_id == envelope_id)
            .where(FederationOutboundQueue.target_relay == home)
            .limit(1)
        )
        existing = (await db.execute(dup_stmt)).scalar_one_or_none()
        if existing is None:
            forward_envelope = {
                "from": body.from_,
                "to": body.to,
                "ts": body.ts,
                "ttl": body.ttl,
                "blob": body.blob,
                "sig": body.sig,
                "from_username": sender_username,
                "group_id": str(group.id),
                "group_forward_mode": "to_host",
            }
            db.add(FederationOutboundQueue(
                envelope_id=envelope_id,
                envelope_data=forward_envelope,
                target_relay=home,
                status=FedQueueStatus.PENDING,
                attempts=0,
                next_attempt_at=now,
                created_at=now,
            ))
            await db.flush()
        logger.info(
            "Forwarding group message %s... to host relay %s",
            envelope_id[:8], home,
        )
        return GroupEnvelopeAck(
            envelope_id=envelope_id,
            queued=True,
            recipient_count=max(0, len(group.members) - 1),
            expires_at=expires_at,
        )

    # ------------------------------------------------------------------
    # CASE 2: I AM the host → store blob, fan out (local + federation).
    # ------------------------------------------------------------------
    await blob_storage.write_blob(envelope_id, blob_bytes)

    envelope_for_fanout = {
        "from": body.from_,
        "to": body.to,
        "ts": body.ts,
        "ttl": body.ttl,
        "blob": body.blob,
        "sig": body.sig,
        "from_username": sender_username,
    }
    local_count, remote_relay_count = await do_group_fanout(
        group=group,
        envelope=envelope_for_fanout,
        envelope_id=envelope_id,
        db=db,
        redis=redis,
    )

    return GroupEnvelopeAck(
        envelope_id=envelope_id,
        queued=True,
        # Approximation: members minus sender. (Some remote relays may
        # have multiple members behind one outbound row.)
        recipient_count=max(0, len(group.members) - 1),
        expires_at=expires_at,
    )


@router.post(
    "/{group_id}/messages/{envelope_id}/delete",
    summary="Delete a group message (sender or group admin)",
)
async def delete_group_message(
    group_id: str,
    envelope_id: str,
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
) -> dict:
    """
    Remove a group message from every member's inbox and push a delete
    event on each member's WS channel.

    Authorization
    -------------
    Caller must be a member of the group AND either:
      - the original sender (verified via envelope metadata while it
        still lives in Redis), or
      - the group's admin.

    If the envelope metadata has already expired or been acked off the
    queue, the original sender cannot be re-derived — in that case only
    a group admin may invoke this endpoint.
    """
    if len(envelope_id) != 64 or not all(
        c in "0123456789abcdef" for c in envelope_id
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_envelope_id",
        )

    gid = _parse_group_id(group_id)
    group = await _load_group(db, gid)
    caller = bytes.fromhex(current.pubkey_hex)

    if not _is_member(group, caller):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="not_a_member",
        )

    meta = await get_envelope_meta(redis, envelope_id)

    sender_pubkey_hex: str | None = None
    if meta is not None:
        if meta.get("group_id") != str(group.id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="envelope_not_in_this_group",
            )
        sender_pubkey_hex = meta.get("from")

    is_sender = (
        sender_pubkey_hex is not None
        and sender_pubkey_hex == current.pubkey_hex
    )
    admin_member = _find_admin(group)
    is_admin = admin_member is not None and admin_member.pubkey == caller

    if not (is_sender or is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="must_be_sender_or_admin",
        )

    recipient_pubkeys_hex = [m.pubkey.hex() for m in group.members]

    result = await delete_envelope_for_group(
        redis=redis,
        envelope_id=envelope_id,
        group_id=str(group.id),
        recipient_pubkeys_hex=recipient_pubkeys_hex,
        deleted_by_pubkey_hex=current.pubkey_hex,
    )

    logger.info(
        "Group %s msg %s... deleted by %s... (sender=%s, admin=%s)",
        group_id, envelope_id[:8], current.pubkey_hex[:8],
        is_sender, is_admin,
    )

    return {
        "deleted": True,
        "envelope_id": envelope_id,
        "deleted_from_count": result["deleted_from_count"],
        "broadcast_to": result["broadcast_to"],
        "meta_existed": result["meta_existed"],
    }


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
