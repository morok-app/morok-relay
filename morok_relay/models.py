"""
Database models.

Design notes:
- We store the MINIMUM possible: pubkeys (32 bytes), usernames if reserved,
  group metadata. NEVER plaintext message content. Encrypted blobs live as
  files on disk (see blob_storage.py), not in the DB.

- All timestamps are UTC, stored as INTEGER (epoch seconds). We don't use
  TIMESTAMP because we want full control and no timezone confusion.

- Pubkeys are stored as BYTEA (32 bytes) for efficient indexing, not hex strings.
  Hex is for display only.

- We use UUIDs for our own IDs (not pubkey-as-PK) because pubkeys can theoretically
  be replaced (key rotation in v2) and we don't want to cascade everything.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    Boolean,
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

if TYPE_CHECKING:
    pass


# ============================================================================
# USER
# ============================================================================

class User(Base):
    """
    A registered user of this relay.

    Identity = Ed25519 public key (32 bytes). Username is optional and
    can be released/changed. Public key is forever.
    """
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    pubkey: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, unique=True, index=True,
        comment="Ed25519 public key — the user's permanent identity.",
    )

    username: Mapped[str | None] = mapped_column(
        String(20), nullable=True, unique=True, index=True,
        comment="Optional human-readable handle. Globally unique across federation.",
    )

    home_relay: Mapped[str] = mapped_column(
        String(255), nullable=False,
        comment="Hostname of the relay where this user resides.",
    )

    created_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=func.extract("epoch", func.now()),
    )

    last_seen_at: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True,
        comment="Last time this user connected. Used only for online indicator.",
    )

    # Soft-delete: when a user wipes their account, we keep the row briefly
    # so federated peers can stop trying to deliver to them, then hard-delete.
    deleted_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


# ============================================================================
# USERNAME RESERVATION (history, for cooldown)
# ============================================================================

class UsernameHistory(Base):
    """
    Track username releases so we can enforce cooldown periods.

    When a user releases @stas, we don't let anyone else claim it for
    N days. This prevents impersonation by squatting on names of people
    who briefly disconnected.
    """
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
    """
    A closed group chat. Up to 50 members.

    Group metadata is stored on the *creator's* home relay. Other relays
    learn about groups through federation when their users are members.

    Encryption: each group has a sender-key shared among members. The relay
    never sees plaintext, never sees the sender-key. We just store membership
    and route encrypted blobs.
    """
    __tablename__ = "groups"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    creator_pubkey: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, index=True,
    )

    # Encrypted name and avatar — stored as opaque blobs because they can
    # contain identifying info. Even relay operator shouldn't read them.
    name_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    is_channel: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False,
        comment="If True, only admins can post (read-only for members).",
    )

    default_ttl_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=86400,
        comment="Default disappearing-message TTL for this group.",
    )

    created_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=func.extract("epoch", func.now()),
    )

    deleted_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    members: Mapped[list["GroupMember"]] = relationship(
        back_populates="group", cascade="all, delete-orphan"
    )


class GroupMember(Base):
    """
    Membership of a user in a group.

    We store pubkey directly (not user FK) because group members can be
    on other relays — we don't have a User row for them locally.
    """
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
    """
    A known peer relay we federate with.

    Populated from DNS TXT records on morok.app and from operator config.
    Each peer has a public key we use to verify signed federation requests.
    """
    __tablename__ = "federation_peers"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    hostname: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)

    pubkey: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False,
        comment="Relay's Ed25519 public key for federation auth.",
    )

    is_trusted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False,
        comment="Operator-curated trust flag. Untrusted peers are rate-limited.",
    )

    last_handshake_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    created_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=func.extract("epoch", func.now()),
    )


# ============================================================================
# AUDIT NOTE
# ============================================================================
# Things we DELIBERATELY do not store:
#
#   - Message content (encrypted or otherwise)         → blobs on filesystem
#   - Message history                                  → deleted post-delivery
#   - Per-user contact lists                           → client-side only
#   - Per-user friend graph                            → client-side only
#   - IP addresses                                     → nginx logs, 24h rotation
#   - Push notification tokens                         → encrypted, weekly rotation
#                                                        (separate table when needed)
#   - Login history                                    → not retained
#
# If you find yourself adding any of the above to this file, STOP and reconsider.
# ============================================================================
