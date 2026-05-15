"""
Database models.

See the audit note at the bottom for what we deliberately don't store.
"""
from __future__ import annotations

import enum
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


# ============================================================================
# USER TIER
# ============================================================================

class UserTier(str, enum.Enum):
    FREE = "free"
    PREMIUM = "premium"
    ADMIN = "admin"


# ============================================================================
# USER
# ============================================================================

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    pubkey: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, unique=True, index=True,
    )
    username: Mapped[str | None] = mapped_column(
        String(20), nullable=True, unique=True, index=True,
    )
    tier: Mapped[UserTier] = mapped_column(
        SAEnum(UserTier, name="user_tier", values_callable=lambda e: [m.value for m in e]),
        nullable=False, default=UserTier.FREE, server_default="free", index=True,
    )
    home_relay: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=func.extract("epoch", func.now()),
    )
    last_seen_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    deleted_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


# ============================================================================
# USERNAME HISTORY
# ============================================================================

class UsernameHistory(Base):
    __tablename__ = "username_history"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    pubkey: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    claimed_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    released_at: Mapped[int] = mapped_column(BigInteger, nullable=False)

    __table_args__ = (
        Index("ix_username_history_username_released", "username", "released_at"),
    )


# ============================================================================
# GROUP — closed groups and channels
# ============================================================================

class Group(Base):
    """
    A closed group chat or one-way channel.

    Membership model
    ----------------
    - Creator is the sole admin in v1.
    - Members join only by being added by the admin (no public join endpoint
      yet; that comes with invite links later).
    - Channels (is_channel=True) restrict write access to the admin.

    Encryption model
    ----------------
    Members share a sender-key, distributed out-of-band (the client encrypts
    the sender-key with each member's X25519 key and stores those in messages
    until everyone receives it). The relay never sees the sender-key.

    Anonymous-sender mode (v1 limitation)
    -------------------------------------
    When anonymous_senders=True, OTHER members can't tell who in the group
    sent a message. The RELAY can — for v1 we trust the relay for that, and
    document the limitation. Full sender-anonymity would require ring
    signatures over group membership (v2 feature).

    Expiry
    ------
    If expires_at is set, the group and ALL its messages are deleted after
    that time. Powers "chats with a predetermined end". The reaper enforces.
    """
    __tablename__ = "groups"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    creator_pubkey: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, index=True,
    )

    # Encrypted display name — relay never sees plaintext.
    name_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    is_channel: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False,
        comment="If True, only admins can post (read-only for members).",
    )

    default_ttl_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=86400,
        comment="Default disappearing-message TTL for this group.",
    )

    # NEW in v0.6
    slug: Mapped[str | None] = mapped_column(
        String(30), nullable=True, unique=True, index=True,
        comment="Custom URL handle for channels (premium feature).",
    )

    expires_at: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True, index=True,
        comment="If set, group is deleted after this epoch second.",
    )

    anonymous_senders: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false",
        comment="If True, member messages appear as from the group itself.",
    )

    max_members: Mapped[int] = mapped_column(
        Integer, nullable=False, default=50, server_default="50",
        comment="Member cap (50 free / 200 premium at creation time).",
    )

    created_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=func.extract("epoch", func.now()),
    )

    deleted_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    members: Mapped[list["GroupMember"]] = relationship(
        back_populates="group", cascade="all, delete-orphan"
    )


class GroupMember(Base):
    __tablename__ = "group_members"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    group_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    pubkey: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, index=True)

    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    joined_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=func.extract("epoch", func.now()),
    )

    group: Mapped["Group"] = relationship(back_populates="members")

    __table_args__ = (
        UniqueConstraint("group_id", "pubkey", name="uq_group_members_group_pubkey"),
    )


# ============================================================================
# FEDERATION PEER
# ============================================================================

class FederationPeer(Base):
    __tablename__ = "federation_peers"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    pubkey: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    is_trusted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_handshake_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=func.extract("epoch", func.now()),
    )
