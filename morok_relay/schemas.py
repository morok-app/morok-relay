"""
Pydantic schemas for API requests and responses.
"""
from __future__ import annotations

import base64
import re

from pydantic import BaseModel, Field, field_validator

# ============================================================================
# AUTH
# ============================================================================

class ChallengeRequest(BaseModel):
    pubkey_hex: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class ChallengeResponse(BaseModel):
    challenge_hex: str
    expires_at: int


class AuthRequest(BaseModel):
    pubkey_hex: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    challenge_hex: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    timestamp: int = Field(..., ge=0)
    signature_hex: str = Field(..., pattern=r"^[0-9a-f]{128}$")


class AuthResponse(BaseModel):
    session_token: str
    expires_at: int
    pubkey_hex: str
    # Дім акаунта (зловлено в проді 17.08): auth видає сесію на БУДЬ-
    # якому релеї — це задумано (відновлення, міграція), але користувач,
    # що залогінився не на свій дім, читає ПОРОЖНІЙ inbox: його
    # повідомлення федеруються на home_relay і чекають там. Клієнт
    # порівнює home_relay з релеєм підключення і показує попередження /
    # пропонує перейти. Поля АДИТИВНІ — старі клієнти їх ігнорують.
    # None = перший вхід узагалі (рядок щойно створено, дім = цей релей).
    home_relay: str | None = None
    is_home_relay: bool = True


class LogoutResponse(BaseModel):
    revoked: bool


# ============================================================================
# USERNAMES
# ============================================================================

USERNAME_CHAR_PATTERN = re.compile(r"^[a-z0-9_]+$")
USERNAME_MAX_LEN = 20

TIER_MIN_LENGTH = {"free": 5, "premium": 3, "admin": 1}

RESERVED_USERNAMES = frozenset({
    "admin", "administrator", "root", "system", "morok", "morok_app",
    "support", "help", "abuse", "security", "official", "team",
    "anonymous", "anon", "null", "undefined", "me", "self",
    "channel", "group", "user", "users",
})


def normalize_username(raw: str) -> str:
    return raw.strip().lstrip("@").lower()


def validate_username_for_tier(username: str, tier: str) -> str:
    normalized = normalize_username(username)
    if not USERNAME_CHAR_PATTERN.match(normalized):
        raise ValueError(
            "Username may only contain lowercase letters, digits, and underscores"
        )
    if normalized[0].isdigit() or normalized[0] == "_":
        raise ValueError("Username cannot start with digit or underscore")
    if len(normalized) > USERNAME_MAX_LEN:
        raise ValueError(f"Username too long (max {USERNAME_MAX_LEN} chars)")
    min_len = TIER_MIN_LENGTH.get(tier, TIER_MIN_LENGTH["free"])
    if len(normalized) < min_len:
        if tier == "free":
            raise ValueError(
                f"Username too short — free accounts need {min_len}+ characters. "
                f"Shorter handles available on premium."
            )
        raise ValueError(
            f"Username too short — {tier} tier needs {min_len}+ characters"
        )
    if normalized in RESERVED_USERNAMES:
        raise ValueError("This username is reserved")
    return normalized


class UsernameClaim(BaseModel):
    username: str

    @field_validator("username")
    @classmethod
    def basic_normalize(cls, v: str) -> str:
        normalized = normalize_username(v)
        if not USERNAME_CHAR_PATTERN.match(normalized):
            raise ValueError(
                "Username may only contain lowercase letters, digits, and underscores"
            )
        if normalized[0].isdigit() or normalized[0] == "_":
            raise ValueError("Username cannot start with digit or underscore")
        if len(normalized) > USERNAME_MAX_LEN:
            raise ValueError(f"Username too long (max {USERNAME_MAX_LEN} chars)")
        if normalized in RESERVED_USERNAMES:
            raise ValueError("This username is reserved")
        return normalized


class UserInfo(BaseModel):
    pubkey_hex: str
    username: str | None
    home_relay: str
    last_seen_at: int | None


class MeInfo(BaseModel):
    pubkey_hex: str
    username: str | None
    home_relay: str
    tier: str
    created_at: int


class UsernameReleaseResponse(BaseModel):
    released: bool
    cooldown_until: int


# ============================================================================
# GROUP SLUGS
# ============================================================================

SLUG_CHAR_PATTERN = re.compile(r"^[a-z0-9_]+$")
SLUG_MIN_LEN = 3
SLUG_MAX_LEN = 20

RESERVED_SLUGS = frozenset({
    "admin", "support", "official", "morok",
    "settings", "dashboard", "channel", "group", "channels", "groups",
    "api", "docs", "help", "about", "terms", "privacy",
    "discover", "trending", "popular", "verified",
})


def normalize_slug(raw: str) -> str:
    return raw.strip().lstrip("/").lstrip("@").lower()


def validate_slug(slug: str) -> str:
    s = normalize_slug(slug)
    if not SLUG_CHAR_PATTERN.match(s):
        raise ValueError(
            "Slug may only contain lowercase letters, digits, and underscores"
        )
    if s[0].isdigit() or s[0] == "_":
        raise ValueError("Slug cannot start with digit or underscore")
    if len(s) < SLUG_MIN_LEN:
        raise ValueError(f"Slug too short (min {SLUG_MIN_LEN} chars)")
    if len(s) > SLUG_MAX_LEN:
        raise ValueError(f"Slug too long (max {SLUG_MAX_LEN} chars)")
    if s in RESERVED_SLUGS:
        raise ValueError("This slug is reserved")
    return s


# ============================================================================
# GROUPS
# ============================================================================

GROUP_NAME_MAX_BYTES = 2048
GROUP_DEFAULT_TTL_MIN = 60
GROUP_DEFAULT_TTL_MAX = 86400


class GroupCreate(BaseModel):
    name_encrypted: str = Field(..., description="base64-encoded encrypted name")
    is_channel: bool = False
    default_ttl_seconds: int = Field(
        default=86400, ge=GROUP_DEFAULT_TTL_MIN, le=GROUP_DEFAULT_TTL_MAX,
    )
    anonymous_senders: bool = False
    expires_at: int | None = Field(default=None, ge=0)
    slug: str | None = None

    @field_validator("name_encrypted")
    @classmethod
    def name_is_valid_base64(cls, v: str) -> str:
        try:
            decoded = base64.b64decode(v, validate=True)
        except Exception:
            raise ValueError("name_encrypted must be valid base64")
        if len(decoded) == 0:
            raise ValueError("name_encrypted is empty")
        if len(decoded) > GROUP_NAME_MAX_BYTES:
            raise ValueError(
                f"name_encrypted too large (max {GROUP_NAME_MAX_BYTES} bytes decoded)"
            )
        return v

    @field_validator("slug")
    @classmethod
    def validate_slug_if_set(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return validate_slug(v)


class GroupMemberInfo(BaseModel):
    pubkey_hex: str
    username: str | None = None
    is_admin: bool
    joined_at: int


class GroupInfo(BaseModel):
    group_id: str
    creator_pubkey_hex: str
    name_encrypted: str
    is_channel: bool
    default_ttl_seconds: int
    anonymous_senders: bool
    expires_at: int | None
    slug: str | None
    max_members: int
    created_at: int
    member_count: int


class GroupInfoDetailed(GroupInfo):
    members: list[GroupMemberInfo]


class GroupAddMemberRequest(BaseModel):
    pubkey_hex: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class GroupMembershipChange(BaseModel):
    group_id: str
    member_pubkey_hex: str
    action: str
    member_count: int


# ============================================================================
# GROUP INVITE TOKENS (Day 6)
# ============================================================================

INVITE_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,40}$")


class InviteTokenCreate(BaseModel):
    """Admin creates a new invite token for their group."""
    # Optional override of TTL; server clamps to [1h .. 30d], default 7d.
    ttl_seconds: int | None = Field(default=None, ge=3600, le=30 * 86400)


class InviteTokenInfo(BaseModel):
    token: str
    group_id: str
    created_by_pubkey_hex: str
    created_at: int
    expires_at: int


class InviteTokenList(BaseModel):
    tokens: list[InviteTokenInfo]


class JoinViaTokenResponse(BaseModel):
    group_id: str
    joined: bool
    member_count: int


# ============================================================================
# MESSAGE ENVELOPE
# ============================================================================

class EnvelopeIn(BaseModel):
    from_: str = Field(..., alias="from", pattern=r"^[0-9a-f]{64}$")
    to: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    ts: int = Field(..., ge=0)
    ttl: int = Field(..., ge=1, le=86400)
    blob: str
    sig: str = Field(..., pattern=r"^[0-9a-f]{128}$")

    model_config = {"populate_by_name": True}


class EnvelopeAck(BaseModel):
    envelope_id: str
    queued: bool
    expires_at: int


class GroupEnvelopeIn(BaseModel):
    from_: str = Field(..., alias="from", pattern=r"^[0-9a-f]{64}$")
    to: str = Field(..., min_length=36, max_length=36)
    ts: int = Field(..., ge=0)
    ttl: int = Field(..., ge=1, le=86400)
    blob: str
    sig: str = Field(..., pattern=r"^[0-9a-f]{128}$")

    model_config = {"populate_by_name": True}


class GroupEnvelopeAck(BaseModel):
    envelope_id: str
    queued: bool
    recipient_count: int
    expires_at: int


# ============================================================================
# DEAD MAN'S SWITCH
# ============================================================================

DMS_TRIGGER_MIN_SECONDS = 3600          # 1 hour
DMS_TRIGGER_MAX_SECONDS = 365 * 86400   # 1 year
DMS_PAYLOAD_MAX_BYTES = 262144          # 256 KB, same as message blob
DMS_FREE_TIER_MAX_RECIPIENTS = 5
DMS_PREMIUM_TIER_MAX_RECIPIENTS = 20
DMS_LABEL_MAX_LEN = 100


class DMSCreate(BaseModel):
    """
    Create a dead man's switch.

    Fields:
    - trigger_seconds: inactivity period that fires the switch (1h to 1y)
    - payload_encrypted: base64 ciphertext to deliver. Relay never decrypts.
    - recipient_pubkeys_hex: 1 to N pubkey hex strings. N depends on tier.
    - label: optional user-visible name like "family". Up to 100 chars.
    """
    trigger_seconds: int = Field(
        ..., ge=DMS_TRIGGER_MIN_SECONDS, le=DMS_TRIGGER_MAX_SECONDS,
    )
    payload_encrypted: str = Field(..., description="base64 ciphertext")
    recipient_pubkeys_hex: list[str] = Field(..., min_length=1)
    label: str | None = Field(default=None, max_length=DMS_LABEL_MAX_LEN)

    @field_validator("payload_encrypted")
    @classmethod
    def payload_is_valid_base64(cls, v: str) -> str:
        try:
            decoded = base64.b64decode(v, validate=True)
        except Exception:
            raise ValueError("payload_encrypted must be valid base64")
        if len(decoded) == 0:
            raise ValueError("payload_encrypted is empty")
        if len(decoded) > DMS_PAYLOAD_MAX_BYTES:
            raise ValueError(
                f"payload_encrypted too large (max {DMS_PAYLOAD_MAX_BYTES} bytes)"
            )
        return v

    @field_validator("recipient_pubkeys_hex")
    @classmethod
    def validate_recipients(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("at least one recipient required")
        seen = set()
        out = []
        for pk in v:
            pk = pk.lower().strip()
            if not re.match(r"^[0-9a-f]{64}$", pk):
                raise ValueError(f"recipient pubkey not 64 hex chars: {pk[:16]}...")
            if pk in seen:
                raise ValueError("duplicate recipient pubkeys not allowed")
            seen.add(pk)
            out.append(pk)
        if len(out) > DMS_PREMIUM_TIER_MAX_RECIPIENTS:
            raise ValueError(
                f"too many recipients (max {DMS_PREMIUM_TIER_MAX_RECIPIENTS} even for premium)"
            )
        return out


class DMSRecipientInfo(BaseModel):
    recipient_pubkey_hex: str
    delivered_at: int | None


class DMSInfo(BaseModel):
    """Full DMS info returned to the owner."""
    dms_id: str
    trigger_seconds: int
    last_check_in_at: int
    fires_at: int
    label: str | None
    status: str
    created_at: int
    triggered_at: int | None
    cancelled_at: int | None
    recipients: list[DMSRecipientInfo]


class DMSCheckInResponse(BaseModel):
    dms_id: str
    last_check_in_at: int
    fires_at: int


class DMSCancelResponse(BaseModel):
    dms_id: str
    cancelled: bool


# ============================================================================
# ENCRYPTED BACKUP
# ============================================================================

BACKUP_MAX_BYTES = 1024
BACKUP_KDF_SALT_BYTES = 16


class BackupCreateRequest(BaseModel):
    encrypted_seed_b64: str = Field(...)
    kdf_salt_b64: str = Field(...)
    kdf_params: dict = Field(default_factory=dict)
    schema_version: int = Field(default=1, ge=1, le=10)

    @field_validator("kdf_params")
    @classmethod
    def _kdf_floor(cls, v: dict) -> dict:
        """
        Серверний мінімум на KDF (аудит зовн. №2, HIGH→CRITICAL).

        Раніше kdf_params був повністю client-defined — сервер зберігав
        будь-який JSON. Слабкий/старий/зламаний клієнт міг створити
        бекап із дешевим KDF, а публічний restore-ендпоінт віддає
        ciphertext за самим username: один запит — і далі offline-
        перебір PIN'а зі швидкістю, яку визначає САМ нападник. Приз —
        seed акаунта.

        Мінімуми нижче — стеля розумного компромісу для мобільних
        пристроїв (klientський Argon2id у Morok і так сильніший):
        argon2id, memory >= 64 MiB, iterations >= 2, parallelism >= 1.
        Бекап зі слабшими параметрами сервер ВІДМОВЛЯЄТЬСЯ зберігати —
        краще голосно зламатись на створенні, ніж тихо віддати
        перебираємий seed на restore.

        Наявні в БД бекапи не чіпаємо: перевірка діє на створення/
        заміну. Порожній dict теж відхиляється — клієнт зобов'язаний
        задекларувати, чим шифрував.
        """
        alg = str(v.get("alg", v.get("algorithm", ""))).lower()
        if alg not in ("argon2id", "argon2"):
            raise ValueError(
                "kdf_params.alg must be argon2id (weak/unknown KDF refused)"
            )
        mem_kib = int(v.get("m", v.get("memory_kib", v.get("memory", 0))))
        iters = int(v.get("t", v.get("iterations", v.get("time", 0))))
        para = int(v.get("p", v.get("parallelism", 1)))
        if mem_kib < 64 * 1024:
            raise ValueError("kdf_params memory must be >= 65536 KiB (64 MiB)")
        if iters < 2:
            raise ValueError("kdf_params iterations must be >= 2")
        if para < 1:
            raise ValueError("kdf_params parallelism must be >= 1")
        return v

    @field_validator("encrypted_seed_b64")
    @classmethod
    def _enc_size(cls, v: str) -> str:
        try:
            decoded = base64.b64decode(v, validate=True)
        except Exception:
            raise ValueError("encrypted_seed_b64 must be valid base64")
        if len(decoded) == 0:
            raise ValueError("encrypted_seed is empty")
        if len(decoded) > BACKUP_MAX_BYTES:
            raise ValueError(f"encrypted_seed too large (max {BACKUP_MAX_BYTES} bytes)")
        return v

    @field_validator("kdf_salt_b64")
    @classmethod
    def _salt_size(cls, v: str) -> str:
        try:
            decoded = base64.b64decode(v, validate=True)
        except Exception:
            raise ValueError("kdf_salt_b64 must be valid base64")
        if len(decoded) != BACKUP_KDF_SALT_BYTES:
            raise ValueError(f"kdf_salt must be {BACKUP_KDF_SALT_BYTES} bytes")
        return v


class BackupInfo(BaseModel):
    encrypted_seed_b64: str
    kdf_salt_b64: str
    kdf_params: dict
    schema_version: int
    created_at: int
    updated_at: int


class BackupRestoreResponse(BaseModel):
    encrypted_seed_b64: str
    kdf_salt_b64: str
    kdf_params: dict
    schema_version: int
    username_at_backup: str | None


class BackupDeleted(BaseModel):
    deleted: bool


# ============================================================================
# HEALTH & ERROR
# ============================================================================

class HealthResponse(BaseModel):
    status: str
    relay_name: str
    version: str
    onion: str | None = None
    onion_supported: bool = False


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None

# ============================================================================
# BURNER INBOX
# ============================================================================

BURNER_LABEL_MAX_LEN = 64
BURNER_SENDER_LABEL_MAX_LEN = 64


class BurnerCreate(BaseModel):
    """Owner creates a new burner link."""
    ttl_seconds: int | None = Field(default=None, ge=3600, le=30 * 86400)
    label: str | None = Field(default=None, max_length=BURNER_LABEL_MAX_LEN)


class BurnerInfo(BaseModel):
    """Returned to the owner."""
    token: str
    owner_pubkey_hex: str
    label: str | None
    created_at: int
    expires_at: int
    message_count: int


class BurnerList(BaseModel):
    tokens: list[BurnerInfo]


class BurnerTokenRevoked(BaseModel):
    token: str
    revoked: bool


class BurnerPublicInfo(BaseModel):
    """
    Returned to anyone with the burner URL — minimal info so they can
    encrypt for the owner. Does NOT reveal anything else about the owner
    (no username, no last-seen, etc).
    """
    owner_pubkey_hex: str
    label: str | None
    expires_at: int


class BurnerSend(BaseModel):
    """
    Payload submitted by an anonymous sender via the public burner endpoint.
    """
    ephemeral_pubkey_hex: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    blob_b64: str = Field(..., description="base64 ciphertext")
    sender_label: str | None = Field(
        default=None, max_length=BURNER_SENDER_LABEL_MAX_LEN,
    )


class BurnerSendAck(BaseModel):
    envelope_id: str
    queued: bool
    expires_at: int | None = None
    message_count: int | None = None
