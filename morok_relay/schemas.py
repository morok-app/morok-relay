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
# GROUPS & CHANNELS
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
# MESSAGE ENVELOPE (1-on-1)
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


# ============================================================================
# GROUP MESSAGE ENVELOPE
# ============================================================================

class GroupEnvelopeIn(BaseModel):
    """
    Envelope for a group message.

    Differs from 1-on-1 EnvelopeIn:
    - 'to' is the group UUID (string), not a recipient pubkey
    - Signature is computed over the same canonical envelope (minus 'sig')

    The blob is shared across all recipients — they decrypt it with the
    shared sender-key.

    For anonymous_senders groups: 'from' is still the real sender pubkey
    (relay needs it to verify the signature), but clients SHOULD render
    the message as from the group itself, not the sender. See API.md.
    """
    from_: str = Field(..., alias="from", pattern=r"^[0-9a-f]{64}$")
    to: str = Field(
        ...,
        description="Group UUID (36 chars including hyphens)",
        min_length=36, max_length=36,
    )
    ts: int = Field(..., ge=0)
    ttl: int = Field(..., ge=1, le=86400)
    blob: str
    sig: str = Field(..., pattern=r"^[0-9a-f]{128}$")

    model_config = {"populate_by_name": True}


class GroupEnvelopeAck(BaseModel):
    envelope_id: str
    queued: bool
    recipient_count: int    # how many members got fan-out'd
    expires_at: int


# ============================================================================
# HEALTH & ERROR
# ============================================================================

class HealthResponse(BaseModel):
    status: str
    relay_name: str
    version: str


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
