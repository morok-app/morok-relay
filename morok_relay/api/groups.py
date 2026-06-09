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

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from .. import blob_storage, crypto, invite_tokens
from ..config import get_settings
from ..deps import CurrentSession, DBSession, RedisClient
from ..models import FederationOutboundQueue, FedQueueStatus, Group, GroupMember, User, UserTier
from ..queue import (
    publish_group_gone,
    delete_envelope_for_group,
    enqueue_envelope_for_recipients,
    envelope_exists,
    get_envelope_meta,
)
from ..push_sender import trigger_push
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
    """
    Return the first admin found, or None.

    NOTE: This returns ONLY ONE admin even when a group has multiple.
    For authorization checks ("is this caller an admin?") use
    `_is_admin(group, caller_bytes)` instead — using `_find_admin().pubkey
    == caller` silently locks out every admin except the first one in
    the member list, which is a subtle multi-admin correctness bug.
    `_find_admin` is still useful for "tell me who the admin is" UI
    queries.
    """
    for m in group.members:
        if m.is_admin:
            return m
    return None


def _is_admin(group: Group, caller_pubkey: bytes) -> bool:
    """
    True if `caller_pubkey` is an admin of `group`. Works correctly when
    a group has multiple admins — the previous `_find_admin().pubkey ==
    caller` pattern only matched the first admin and rejected the rest.
    """
    for m in group.members:
        if m.is_admin and m.pubkey == caller_pubkey:
            return True
    return False


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
    redis: RedisClient,
) -> dict:
    gid = _parse_group_id(group_id)
    group = await _load_group(db, gid)
    pubkey = bytes.fromhex(current.pubkey_hex)
    if group.creator_pubkey != pubkey:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="only_creator_can_delete",
        )
    # Collect member pubkeys BEFORE tombstoning, so we can notify them.
    member_pubkeys = [
        m.pubkey.hex() for m in group.members
        if m.pubkey != pubkey
    ]
    group.deleted_at = int(time.time())

    # Real-time push to local members: "this group is gone". Members on
    # other relays learn about it lazily (404 on next group refresh in
    # the client). Best-effort — failures here must not fail the delete.
    try:
        await publish_group_gone(
            redis, member_pubkeys, str(group.id), current.pubkey_hex,
        )
    except Exception:
        pass

    return {"deleted": True, "group_id": str(group.id)}


@router.post("/{group_id}/members", response_model=GroupMembershipChange)
async def add_member(
    group_id: str, body: GroupAddMemberRequest,
    current: CurrentSession, db: DBSession,
) -> GroupMembershipChange:
    gid = _parse_group_id(group_id)
    group = await _load_group(db, gid)
    caller = bytes.fromhex(current.pubkey_hex)
    if not _is_admin(group, caller):
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

    # Push fresh snapshot to every peer relay that hosts at least one
    # member (including the newly added one). Worker delivers async.
    member_bytes = [m.pubkey for m in group.members]
    peer_relays = await _peer_relays_for_members(db, member_bytes)
    if peer_relays:
        await enqueue_snapshot_to_relays(db, group, peer_relays)
        logger.info(
            "Group %s: snapshot queued to %d peer relay(s) after add_member",
            group.id, len(peer_relays),
        )

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
    is_admin = _is_admin(group, caller)
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
    # Capture peer relays BEFORE removing — so a relay losing its last
    # local member also gets the final snapshot (member_count drops).
    member_bytes_before = [m.pubkey for m in group.members]
    peer_relays = await _peer_relays_for_members(db, member_bytes_before)

    await db.delete(target_member)
    await db.flush()
    await db.refresh(group, attribute_names=["members"])

    if peer_relays:
        await enqueue_snapshot_to_relays(db, group, peer_relays)
        logger.info(
            "Group %s: snapshot queued to %d peer relay(s) after remove_member",
            group.id, len(peer_relays),
        )

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


def _synthetic_queue_id(prefix: str, *parts: str) -> str:
    """
    Deterministic, dedup-friendly synthetic envelope_id for control-plane
    federation rows (snapshots, deletes). Result fits the 64-char column.

    The prefix is a short tag (e.g. "snap", "del", "dmdel") so the row
    is identifiable in DB inspection; the hash of all parts ensures
    repeats with the same intent dedupe naturally.
    """
    import hashlib
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\x00")
    digest = h.hexdigest()
    max_hash_len = 64 - len(prefix) - 1
    if max_hash_len <= 0:
        # Prefix too long; fall back to pure hash.
        return digest[:64]
    return f"{prefix}-{digest[:max_hash_len]}"


def _serialize_group_for_snapshot(group: Group) -> dict:
    """
    Turn a Group ORM row (with members loaded) into the JSON payload
    that peer relays expect on /forward with kind='group_snapshot'.
    """
    return {
        "kind": "group_snapshot",
        "group_id": str(group.id),
        "creator_pubkey_hex": group.creator_pubkey.hex(),
        "name_encrypted_b64": base64.b64encode(group.name_encrypted).decode("ascii"),
        "is_channel": group.is_channel,
        "default_ttl_seconds": group.default_ttl_seconds,
        "slug": group.slug,
        "expires_at": group.expires_at,
        "anonymous_senders": group.anonymous_senders,
        "max_members": group.max_members,
        "home_relay": group.home_relay or get_settings().relay_name,
        "members": [
            {
                "pubkey_hex": m.pubkey.hex(),
                "is_admin": m.is_admin,
                "joined_at": m.joined_at,
            }
            for m in group.members
        ],
        "snapshotted_at": int(time.time()),
    }


async def enqueue_snapshot_to_relays(
    db,
    group: Group,
    target_relays: set[str],
) -> int:
    """
    Push the current group snapshot into federation_outbound_queue for
    each target_relay in the set. Worker will deliver to peer's /forward
    where the kind='group_snapshot' branch upserts the shadow row.

    Uses an envelope_id derived from group_id + version-ish marker so
    repeated snapshots for the same group can be re-queued (dedup is
    target_relay-scoped via DB unique check only if we add one; for now
    multiple pending snapshots are tolerated — the latest wins on apply).
    """
    settings = get_settings()
    if not target_relays:
        return 0
    payload = _serialize_group_for_snapshot(group)
    now = int(time.time())
    pushed = 0
    for target in target_relays:
        if target == settings.relay_name:
            continue
        # snapshot can repeat per add_member; include `now` so each call
        # gets a fresh row instead of dedup'ing with previous snapshots.
        sid = _synthetic_queue_id("snap", str(group.id), str(now), target)
        db.add(FederationOutboundQueue(
            envelope_id=sid,
            envelope_data=payload,
            target_relay=target,
            status=FedQueueStatus.PENDING,
            attempts=0,
            next_attempt_at=now,
            created_at=now,
        ))
        pushed += 1
    if pushed:
        await db.flush()
    return pushed


async def _peer_relays_for_members(
    db,
    member_pubkeys_bytes: list[bytes],
) -> set[str]:
    """Return the set of OTHER relays that host any of the given members."""
    settings = get_settings()
    if not member_pubkeys_bytes:
        return set()
    stmt = (
        select(User.home_relay)
        .where(User.pubkey.in_(member_pubkeys_bytes))
        .where(User.deleted_at.is_(None))
    )
    rows = (await db.execute(stmt)).all()
    return {
        hr for (hr,) in rows
        if hr and hr != settings.relay_name
    }


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
        # Best-effort push fanout to offline members on THIS relay. Members
        # on peer relays receive their push via the federation handler on
        # the receiving end (api/federation.py _handle_group_send_deliver).
        try:
            await trigger_push(
                db=db, redis=redis,
                recipient_pubkeys_hex=local_recipients,
                sender_username=envelope.get("from_username"),
                group_id=str(group.id),
            )
        except Exception as e:
            logger.warning("trigger_push (group local) failed: %s", e)

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
        if not _is_admin(group, sender_pubkey):
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


class GroupDeleteRequest(BaseModel):
    # Sender's Ed25519 signature over canonical_json({
    #   "kind": "group_delete",
    #   "group_id": "<group_uuid>",
    #   "envelope_id": "<envelope_id>",
    #   "ts": <ts>,
    # }) — verified against current.pubkey_hex and forwarded unchanged
    # through the federation hop chain (sender → host → other relays)
    # so each delivering relay can verify cryptographically.
    signature_hex: str = Field(
        ..., min_length=128, max_length=128,
        pattern=r"^[0-9a-fA-F]{128}$",
    )
    ts: int = Field(..., ge=0)


@router.post(
    "/{group_id}/messages/{envelope_id}/delete",
    summary="Delete a group message (sender or group admin)",
)
async def delete_group_message(
    group_id: str,
    envelope_id: str,
    body: GroupDeleteRequest,
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
    settings = get_settings()

    # ── Verify sender signature on the delete request ──────────────────
    # A trusted federation peer must not be able to fabricate "alice
    # deleted msg X" — that's a censorship vector. The caller signs
    # their intent here, the signature is forwarded unchanged through
    # the host hop (case A) and the per-relay deliver hops (case B),
    # and each receiving relay verifies it against deleted_by_pubkey.
    now = int(time.time())
    if abs(now - body.ts) > 7 * 86400:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="delete_ts_out_of_window",
        )
    sig_message = crypto.canonical_json({
        "kind":        "group_delete",
        "group_id":    str(gid),
        "envelope_id": envelope_id,
        "ts":          body.ts,
    })
    try:
        sig_bytes = bytes.fromhex(body.signature_hex)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_signature",
        )
    if not crypto.ed25519_verify(sig_message, sig_bytes, caller):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_delete_signature",
        )

    if not _is_member(group, caller):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="not_a_member",
        )

    home = _group_home_relay(group)

    # ------------------------------------------------------------------
    # Case A: I'm NOT the host → forward the delete request to the host.
    # The host does the real authorization (sender or admin) and the
    # actual fan-out of "deleted" events.
    # ------------------------------------------------------------------
    if home != settings.relay_name:
        delete_payload = {
            "kind": "group_delete_to_host",
            "group_id": str(group.id),
            "envelope_id": envelope_id,
            "deleted_by_pubkey_hex": current.pubkey_hex,
            # Sender's signature, forwarded so host can verify the
            # delete intent rather than trusting our forwarding hop.
            "deleter_signature_hex": body.signature_hex,
            "deleter_ts": body.ts,
        }
        synthetic_id = _synthetic_queue_id("del", envelope_id, home)
        dup_stmt = (
            select(FederationOutboundQueue)
            .where(FederationOutboundQueue.envelope_id == synthetic_id)
            .where(FederationOutboundQueue.target_relay == home)
            .limit(1)
        )
        existing = (await db.execute(dup_stmt)).scalar_one_or_none()
        if existing is None:
            now = int(time.time())
            db.add(FederationOutboundQueue(
                envelope_id=synthetic_id,
                envelope_data=delete_payload,
                target_relay=home,
                status=FedQueueStatus.PENDING,
                attempts=0,
                next_attempt_at=now,
                created_at=now,
            ))
            await db.flush()
        logger.info(
            "Forwarding group delete %s... to host %s",
            envelope_id[:8], home,
        )
        return {
            "deleted": True,
            "envelope_id": envelope_id,
            "forwarded_to_host": home,
        }

    # ------------------------------------------------------------------
    # Case B: I AM the host. Authorize via meta (sender) or admin.
    # ------------------------------------------------------------------
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
    is_admin = _is_admin(group, caller)

    if not (is_sender or is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="must_be_sender_or_admin",
        )

    # Split members by home_relay (same pattern as do_group_fanout).
    member_pubkeys_bytes = [m.pubkey for m in group.members]
    home_by_pubkey_hex: dict[str, str | None] = {}
    if member_pubkeys_bytes:
        stmt = (
            select(User.pubkey, User.home_relay)
            .where(User.pubkey.in_(member_pubkeys_bytes))
            .where(User.deleted_at.is_(None))
        )
        rows = (await db.execute(stmt)).all()
        for pk, hr in rows:
            home_by_pubkey_hex[bytes(pk).hex()] = hr

    local_recipients: list[str] = []
    remote_by_relay: dict[str, list[str]] = {}
    for m in group.members:
        pk_hex = m.pubkey.hex()
        h = home_by_pubkey_hex.get(pk_hex)
        if h is None or h == settings.relay_name:
            local_recipients.append(pk_hex)
        else:
            remote_by_relay.setdefault(h, []).append(pk_hex)

    # Local fan-out delete
    result = await delete_envelope_for_group(
        redis=redis,
        envelope_id=envelope_id,
        group_id=str(group.id),
        recipient_pubkeys_hex=local_recipients,
        deleted_by_pubkey_hex=current.pubkey_hex,
    )

    # Federation: per remote relay, tell it which local-to-it members
    # should drop this envelope.
    now = int(time.time())
    for target_relay, members_on_relay in remote_by_relay.items():
        deliver_payload = {
            "kind": "group_delete_deliver",
            "group_id": str(group.id),
            "envelope_id": envelope_id,
            "deleted_by_pubkey_hex": current.pubkey_hex,
            "deliver_to_pubkeys": members_on_relay,
            # Original sender's signature forwarded unchanged so each
            # receiving relay can verify (not trust the host's fan-out).
            "deleter_signature_hex": body.signature_hex,
            "deleter_ts": body.ts,
        }
        synthetic_id = _synthetic_queue_id("deldlv", envelope_id, target_relay)
        dup_stmt = (
            select(FederationOutboundQueue)
            .where(FederationOutboundQueue.envelope_id == synthetic_id)
            .where(FederationOutboundQueue.target_relay == target_relay)
            .limit(1)
        )
        existing = (await db.execute(dup_stmt)).scalar_one_or_none()
        if existing is None:
            db.add(FederationOutboundQueue(
                envelope_id=synthetic_id,
                envelope_data=deliver_payload,
                target_relay=target_relay,
                status=FedQueueStatus.PENDING,
                attempts=0,
                next_attempt_at=now,
                created_at=now,
            ))
    if remote_by_relay:
        await db.flush()

    logger.info(
        "Group %s msg %s... deleted by %s (sender=%s, admin=%s), local=%d remote_relays=%d",
        group_id, envelope_id[:8], current.pubkey_hex[:8],
        is_sender, is_admin, len(local_recipients), len(remote_by_relay),
    )

    return {
        "deleted": True,
        "envelope_id": envelope_id,
        "deleted_from_count": result["deleted_from_count"],
        "broadcast_to": result["broadcast_to"],
        "meta_existed": result["meta_existed"],
        "federated_to_relays": len(remote_by_relay),
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
    if not _is_admin(group, caller):
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
    if not _is_admin(group, caller):
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
    if not _is_admin(group, caller):
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


# ============================================================================
# CROSS-RELAY GROUP SYNC (on-demand fetch from host)
# ============================================================================

@router.post(
    "/{group_id}/sync",
    summary="Pull a group snapshot from its host relay (peer client triggers)",
)
async def sync_group_from_host(
    group_id: str,
    current: CurrentSession,
    db: DBSession,
    host_relay: str = Query(..., min_length=3, max_length=255,
                             description="Host relay hostname where the group lives"),
) -> dict:
    """
    Client-side trigger: peer relay reaches out to host relay and pulls
    the current group snapshot, upserts it locally.

    Used after a peer-side user gets a `group_key` DM from someone but
    has no local row for the group yet (so /groups/{id} would 404). Once
    synced, normal send/delete endpoints on this peer relay can run
    because `_load_group` finds the shadow row.

    Authentication: caller must be the eventually-included member — but
    we can't verify that without already having the group. So we just
    require an authenticated session (any logged-in user) and rate-limit.
    The host relay returns 404 if the caller isn't a member of the
    requested group, so we can't fetch arbitrary groups.
    """
    settings = get_settings()

    if host_relay == settings.relay_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="host_is_self_no_sync_needed",
        )

    try:
        gid = uuid.UUID(group_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_group_id",
        )

    from ..federation_client import remote_pull_group_snapshot
    snapshot = await remote_pull_group_snapshot(
        peer_hostname=host_relay,
        group_id=str(gid),
        caller_pubkey_hex=current.pubkey_hex,
    )
    if snapshot is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="snapshot_unavailable_from_host",
        )

    # Apply locally (idempotent upsert). The host we asked to pull from
    # IS the authoritative host for this group — that's what makes this
    # operation meaningful in the first place — so it serves as our
    # expected_home_relay.
    await apply_group_snapshot(db, snapshot, expected_home_relay=host_relay)
    await db.flush()

    return {
        "synced": True,
        "group_id": str(gid),
        "host_relay": host_relay,
        "member_count": len(snapshot.get("members", [])),
    }


async def apply_group_snapshot(
    db,
    snapshot: dict,
    *,
    expected_home_relay: str,
) -> Group:
    """
    Idempotent upsert of a group + its members from a snapshot payload.
    Called from /federation/forward (push direction) and /groups/{id}/sync
    (pull direction).

    `expected_home_relay` is the hostname of the relay that is allowed to
    push this snapshot — for federation pushes that's the verified peer
    hostname (NOT a field in the envelope), for sync-pulls it's the host
    the caller asked us to pull from. This blocks two abuses:

      * A trusted peer X tries to push a snapshot for a group whose
        actual host is Y. We refuse — only the host can modify membership.
      * A trusted peer X pushes a brand-new group with `home_relay=Y`
        in the payload, trying to plant a malicious group on the network
        with someone else's hostname. We ignore the payload field and
        record X as the host (which is true: X just sent it to us).

    Legacy rows where home_relay is NULL get the field filled in from
    expected_home_relay — there's no prior owner to defer to.
    """
    if not expected_home_relay:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="snapshot_missing_expected_home_relay",
        )

    try:
        gid = uuid.UUID(snapshot["group_id"])
        creator_bytes = bytes.fromhex(snapshot["creator_pubkey_hex"])
        name_bytes = base64.b64decode(snapshot["name_encrypted_b64"], validate=True)
    except (KeyError, ValueError, TypeError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"malformed_snapshot: {e}",
        )

    stmt = (
        select(Group)
        .options(selectinload(Group.members))
        .where(Group.id == gid)
    )
    existing = (await db.execute(stmt)).scalar_one_or_none()

    if existing is None:
        # New group: home_relay is determined by the verified sender,
        # NEVER trusted from the payload. This prevents a malicious peer
        # from creating a group locally whose "host" is some other relay
        # they don't actually control.
        group = Group(
            id=gid,
            creator_pubkey=creator_bytes,
            name_encrypted=name_bytes,
            is_channel=bool(snapshot.get("is_channel", False)),
            default_ttl_seconds=int(snapshot.get("default_ttl_seconds", 86400)),
            slug=snapshot.get("slug"),
            expires_at=snapshot.get("expires_at"),
            anonymous_senders=bool(snapshot.get("anonymous_senders", False)),
            max_members=int(snapshot.get("max_members", 50)),
            home_relay=expected_home_relay,
        )
        db.add(group)
        await db.flush()
        # No members yet — they get added below.
    else:
        # Existing group: only the recorded host may push updates.
        # Legacy rows (home_relay NULL) get adopted by the first pushing
        # peer — there's no prior claim to honour.
        if existing.home_relay and existing.home_relay != expected_home_relay:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"snapshot_from_wrong_host: group hosted on "
                    f"{existing.home_relay!r}, push came from "
                    f"{expected_home_relay!r}"
                ),
            )
        if not existing.home_relay:
            existing.home_relay = expected_home_relay

        # Overwrite mutable fields — only the host can do this, which is
        # now enforced above.
        existing.is_channel = bool(snapshot.get("is_channel", existing.is_channel))
        existing.default_ttl_seconds = int(
            snapshot.get("default_ttl_seconds", existing.default_ttl_seconds)
        )
        existing.anonymous_senders = bool(
            snapshot.get("anonymous_senders", existing.anonymous_senders)
        )
        existing.max_members = int(snapshot.get("max_members", existing.max_members))
        group = existing

    # Reconcile members. Members listed in snapshot are authoritative.
    snap_pubkeys: dict[bytes, dict] = {}
    for m in snapshot.get("members", []):
        try:
            pk = bytes.fromhex(m["pubkey_hex"])
        except (KeyError, ValueError, TypeError):
            continue
        snap_pubkeys[pk] = m

    # Fetch existing members
    cur_stmt = select(GroupMember).where(GroupMember.group_id == group.id)
    existing_members = list((await db.execute(cur_stmt)).scalars())
    existing_by_pk = {m.pubkey: m for m in existing_members}

    # Remove members no longer in snapshot
    for pk, member in existing_by_pk.items():
        if pk not in snap_pubkeys:
            await db.delete(member)

    # Add or update members from snapshot
    for pk, m in snap_pubkeys.items():
        if pk in existing_by_pk:
            existing_member = existing_by_pk[pk]
            existing_member.is_admin = bool(m.get("is_admin", existing_member.is_admin))
        else:
            db.add(GroupMember(
                group_id=group.id,
                pubkey=pk,
                is_admin=bool(m.get("is_admin", False)),
                joined_at=int(m.get("joined_at", int(time.time()))),
            ))

    await db.flush()
    await db.refresh(group, attribute_names=["members"])
    return group
