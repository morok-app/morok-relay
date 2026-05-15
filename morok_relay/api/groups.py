"""
Group and channel endpoints.

POST    /api/v1/groups                                   — create group/channel
GET     /api/v1/groups                                   — list groups I'm a member of
GET     /api/v1/groups/{group_id}                        — full details + members
DELETE  /api/v1/groups/{group_id}                        — delete (creator only)
POST    /api/v1/groups/{group_id}/members                — admin adds a member
DELETE  /api/v1/groups/{group_id}/members/{pubkey_hex}   — leave self or admin kicks
GET     /api/v1/groups/by-slug/{slug}                    — public lookup for channels

Not yet (sub-session B): POST /api/v1/groups/{group_id}/messages — broadcast.

Tier limits
-----------
- Free creator:    50 members max, slug not allowed
- Premium creator: 200 members max, slug allowed

Limits are recorded on the Group row at creation time and don't change if
the creator's tier changes later. This means a free user who later goes
premium keeps their existing 50-member groups, but new groups they create
get the 200 cap.

Admin model in v1
-----------------
Creator is the sole admin. No way to promote/demote yet. To "transfer
ownership", the creator deletes the group and a new one is created.

Anonymous senders
-----------------
If anonymous_senders=True at creation, member messages to the group will
be presented (by clients) as from the group itself, not the sender. The
RELAY still sees who sent it — this is anonymity *toward other members*,
not *toward the relay*. Documented in API.md.
"""
from __future__ import annotations

import base64
import time
import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..deps import CurrentSession, DBSession
from ..models import Group, GroupMember, User, UserTier
from ..schemas import (
    GroupAddMemberRequest,
    GroupCreate,
    GroupInfo,
    GroupInfoDetailed,
    GroupMemberInfo,
    GroupMembershipChange,
)

router = APIRouter(tags=["groups"])

# Tier-based caps for new groups
FREE_TIER_MAX_MEMBERS = 50
PREMIUM_TIER_MAX_MEMBERS = 200


# ============================================================================
# Helpers
# ============================================================================

async def _get_current_user(db, pubkey_hex: str) -> User:
    """Load the authenticated user. Must exist — they hit auth already."""
    pubkey = bytes.fromhex(pubkey_hex)
    stmt = select(User).where(User.pubkey == pubkey)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if user is None:
        # Lazy-create the user row, matching what users.py does
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
    """
    Create a group. The caller becomes the sole admin.

    Free users get max_members=50 and cannot set a slug.
    Premium users get max_members=200 and may set a slug (3-20 chars).
    """
    user = await _get_current_user(db, current.pubkey_hex)
    now = int(time.time())

    # Tier-based gating
    if user.tier == UserTier.PREMIUM or user.tier == UserTier.ADMIN:
        max_members = PREMIUM_TIER_MAX_MEMBERS
    else:
        max_members = FREE_TIER_MAX_MEMBERS

    if body.slug is not None and user.tier == UserTier.FREE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="slug_requires_premium",
        )

    # Slug uniqueness check
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

    # expires_at sanity — must be in the future, and not absurdly far out
    # (cap at 1 year so people can't game it; reaper still enforces 24h
    # per-message hard cap regardless)
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

    # Decode encrypted name (Pydantic already validated it's valid b64+size)
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
    await db.flush()  # need group.id for FK below

    # Creator joins as admin
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
    """
    Returns groups where the authenticated user is a member.

    No pagination yet (max ~200 groups per user expected at this scale).
    """
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
    """Full info including members. Only members can see this."""
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
    Soft-deletes the group (sets deleted_at). The reaper will clean up
    associated messages and the row itself within 24 hours.

    Only the creator can delete. In v1 there's no concept of multiple
    admins, so creator == sole admin == only one who can delete.

    Returns {"deleted": true, "group_id": ...}. (We don't use 204 because
    FastAPI does not allow a response body with status 204.)
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
    # Members are CASCADE'd by FK when the row is physically deleted later.
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
    """
    Only an admin can add a new member. In v1, admin = creator.

    Idempotent: adding an existing member is a no-op (returns 200 with
    current member_count).
    """
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

    # Idempotent check
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
    """
    Either the user leaves themselves (caller pubkey == target), or the
    admin kicks (caller is admin).

    The creator cannot leave or be kicked. They must delete the group
    instead. This prevents an admin-less zombie state in v1 (where we
    have no admin promotion).
    """
    gid = _parse_group_id(group_id)
    group = await _load_group(db, gid)

    if len(pubkey_hex) != 64 or not all(c in "0123456789abcdef" for c in pubkey_hex):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_pubkey",
        )

    caller = bytes.fromhex(current.pubkey_hex)
    target = bytes.fromhex(pubkey_hex)

    # Auth: caller is either themselves (leaving) or the admin (kicking)
    is_self = caller == target
    admin_member = _find_admin(group)
    is_admin = admin_member is not None and admin_member.pubkey == caller
    if not (is_self or is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="must_be_self_or_admin",
        )

    # Creator can't be removed via this endpoint
    if target == group.creator_pubkey:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="creator_cannot_leave_must_delete_group",
        )

    # Find and remove
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
    """
    Public lookup — no auth. Used to find a channel by its custom URL.

    Returns the same info as the authenticated GET /groups/{id}, but
    without the member list (privacy).
    """
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
