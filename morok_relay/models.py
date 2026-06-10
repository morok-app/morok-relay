"""
Database models.
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
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
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
    ARMED = "armed"
    TRIGGERED = "triggered"
    CANCELLED = "cancelled"


class FedQueueStatus(str, enum.Enum):
    PENDING = "pending"
    IN_FLIGHT = "in_flight"
    SUCCEEDED = "succeeded"
    DEAD_LETTER = "dead_letter"


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
    is_channel: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
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
    home_relay: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True,
        comment="Relay hostname that owns this group in its DB. Members "
                "on other relays route their sends through federation. "
                "NULL = legacy row, treated as the current relay.",
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
# FEDERATION
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


class FederationOutboundQueue(Base):
    __tablename__ = "federation_outbound_queue"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    envelope_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    envelope_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    target_relay: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[FedQueueStatus] = mapped_column(
        SAEnum(
            FedQueueStatus,
            name="fed_queue_status",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False, default=FedQueueStatus.PENDING, server_default="pending",
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    next_attempt_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    delivered_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    __table_args__ = (
        Index("ix_fed_queue_status_next_attempt", "status", "next_attempt_at"),
        Index("ix_fed_queue_target_status", "target_relay", "status"),
    )


# ============================================================================
# ENCRYPTED BACKUP (NEW in v1.0)
# ============================================================================

class EncryptedBackup(Base):
    """
    Zero-knowledge encrypted seed backup for premium users.

    Client encrypts their seed locally with a PIN-derived key (PBKDF2/scrypt
    over a 16-byte salt we generate), then uploads the ciphertext. We store
    bytes — never see the seed in plaintext.

    To restore on a new device, client:
      1. Hits GET /api/v1/backup/by-username/{u} with their username
         (unauthenticated — they don't have a session yet)
      2. We return encrypted_seed + kdf_salt + kdf_params
      3. Client derives key from PIN+salt, decrypts, gets seed, derives pubkey,
         and they're back in.

    Rate limits on the by-username endpoint prevent online brute-force.
    The PIN's offline strength is the client's responsibility — clients
    should enforce 12+ char passphrases (this is in docs, not API).

    One backup per pubkey. Re-POST overwrites.
    """
    __tablename__ = "encrypted_backups"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    pubkey: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, unique=True, index=True,
    )
    username_at_backup: Mapped[str | None] = mapped_column(
        String(20), nullable=True, index=True,
        comment="Snapshot of username at backup time. Used for restore lookup "
                "even if user changed username later.",
    )
    encrypted_seed: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False,
        comment="Client-encrypted seed bytes. Relay never decrypts.",
    )
    kdf_salt: Mapped[bytes] = mapped_column(LargeBinary(16), nullable=False)
    kdf_params: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default="{}",
        comment="Client-defined KDF parameters: algorithm, iterations, etc.",
    )
    schema_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1",
    )
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    updated_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


# ============================================================================
# DEAD MAN'S SWITCH
# ============================================================================

class DeadManSwitch(Base):
    __tablename__ = "dead_man_switches"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    creator_pubkey: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    trigger_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    last_check_in_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    payload_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    label: Mapped[str | None] = mapped_column(String(100), nullable=True)
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
    recipient_pubkey: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    delivered_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    dms: Mapped["DeadManSwitch"] = relationship(back_populates="recipients")

    __table_args__ = (
        UniqueConstraint("dms_id", "recipient_pubkey", name="uq_dms_recipients"),
    )


# ============================================================================
# WEB PUSH SUBSCRIPTIONS
# ============================================================================

class PushSubscription(Base):
    """
    Browser web push subscription. One row per (user, device-endpoint).

    Endpoints are issued by the push provider (Mozilla autopush, Google
    FCM endpoint, Apple's push service for installed PWAs). We treat
    them as opaque URLs to POST to with a VAPID-signed payload.

    `p256dh` and `auth` are subscription-specific keys from the browser;
    pywebpush uses them to encrypt the payload (RFC 8291). They're
    base64url-encoded strings.

    Dead subscriptions (push provider returns 404/410) are deleted by
    the push sender automatically — no separate sweeper needed.
    """
    __tablename__ = "push_subscriptions"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    pubkey: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, index=True,
    )
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    p256dh: Mapped[str] = mapped_column(String(255), nullable=False)
    auth: Mapped[str] = mapped_column(String(255), nullable=False)
    # 'webpush' — браузерна підписка (VAPID, pywebpush, payload шифрується
    # end-to-end до браузера за RFC 8291).
    # 'fcm' — нативний Android (Firebase Cloud Messaging): endpoint = FCM
    # device token, p256dh/auth = ''. Payload FCM читається Google, тому
    # туди НІКОЛИ не кладемо нічого, крім generic-тексту (див. push_sender).
    platform: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="webpush",
    )
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False,
        server_default=func.extract("epoch", func.now()),
    )
    updated_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False,
        server_default=func.extract("epoch", func.now()),
    )
    last_used_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    __table_args__ = (
        UniqueConstraint("pubkey", "endpoint", name="uq_push_pubkey_endpoint"),
    )


# ============================================================================
# LOGIN AUDIT LOG
# ============================================================================

class LoginLog(Base):
    """
    Audit log of successful authentications — one row per /auth/verify
    that returned a session.

    Privacy strategy:
      - We NEVER store the raw IP. Instead, sha256(daily_salt || ip) is
        recorded, where daily_salt rotates every UTC midnight. So an
        operator with DB access can confirm that two logins came from
        the same network within a 24h window, but linkability evaporates
        after the salt rolls over.
      - daily_salt = sha256(relay_privkey || UTC date string). If the
        relay's private key were ever exfiltrated, hashes from that day
        could in theory be brute-forced against a precomputed dictionary
        of all IPv4 — but after the salt rotates, the window closes.
      - user_agent is truncated to 255 chars.
      - We keep at most 30 rows per pubkey; older entries are pruned on
        insert.
    """
    __tablename__ = "login_log"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    pubkey: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, index=True,
    )
    created_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False, index=True,
    )
    ip_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
