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
# ENUMS
# ============================================================================

class UserTier(str, enum.Enum):
    FREE = "free"
    PREMIUM = "premium"
    ADMIN = "admin"


class DMSStatus(str, enum.Enum):
    ARMED = "armed"           # active, will fire on inactivity
    TRIGGERED = "triggered"   # has fired, payload delivered
    CANCELLED = "cancelled"   # owner cancelled before trigger


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
# GROUP
# ============================================================================

class Group(Base):
    __tablename__ = "groups"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    creator_pubkey: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, index=True,
    )
    name_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    is_channel: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False,
    )
    default_ttl_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=86400,
    )
    slug: Mapped[str | None] = mapped_column(
        String(30), nullable=True, unique=True, index=True,
    )
    expires_at: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True, index=True,
    )
    anonymous_senders: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false",
    )
    max_members: Mapped[int] = mapped_column(
        Integer, nullable=False, default=50, server_default="50",
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


# ============================================================================
# DEAD MAN'S SWITCH (NEW in v0.7)
# ============================================================================

class DeadManSwitch(Base):
    """
    A user's pre-armed "if I disappear, send this" mechanism.

    The user creates a DMS with:
    - a trigger_seconds (1h to 1y) of inactivity that fires it
    - an encrypted payload (relay never sees plaintext)
    - 1-20 recipient pubkeys

    On every authenticated request, last_check_in_at is bumped to now. The
    DMS cron (hourly) finds 'armed' switches where now - last_check_in_at
    exceeds trigger_seconds, and fires them: delivers the payload as a
    standard envelope to each recipient.

    After firing, status becomes 'triggered'. A switch can be 'cancelled'
    by the owner at any time, which prevents future firing without losing
    history.
    """
    __tablename__ = "dead_man_switches"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    creator_pubkey: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False,
    )
    trigger_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False,
    )
    last_check_in_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False,
    )
    payload_encrypted: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False,
    )
    label: Mapped[str | None] = mapped_column(
        String(100), nullable=True,
        comment="User-visible label like 'family' or 'work'. Stored as the user provides it — clients may encrypt it client-side or send plaintext.",
    )
    status: Mapped[DMSStatus] = mapped_column(
        SAEnum(DMSStatus, name="dms_status", values_callable=lambda e: [m.value for m in e]),
        nullable=False, default=DMSStatus.ARMED, server_default="armed",
    )
    created_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=func.extract("epoch", func.now()),
    )
    triggered_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cancelled_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    recipients: Mapped[list["DMSRecipient"]] = relationship(
        back_populates="dms", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_dms_creator_status", "creator_pubkey", "status"),
        Index("ix_dms_status_check_in", "status", "last_check_in_at"),
    )


class DMSRecipient(Base):
    __tablename__ = "dms_recipients"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    dms_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("dead_man_switches.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    recipient_pubkey: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False,
    )
    delivered_at: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True,
        comment="When the trigger actually delivered to this recipient.",
    )

    dms: Mapped["DeadManSwitch"] = relationship(back_populates="recipients")

    __table_args__ = (
        UniqueConstraint("dms_id", "recipient_pubkey", name="uq_dms_recipients"),
    )
