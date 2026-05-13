"""
Pydantic schemas for API requests and responses.

These define the wire format. Database models (models.py) are different —
those define what's stored. Schemas are what clients see.
"""
from __future__ import annotations

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
# USER & USERNAME
# ============================================================================

# Character class — what's allowed inside a username (any length).
USERNAME_CHAR_PATTERN = re.compile(r"^[a-z0-9_]+$")

# Length limits per tier — keep in sync with models.UserTier values.
TIER_MIN_LENGTH = {
    "free": 5,
    "premium": 3,
    "admin": 1,
}
USERNAME_MAX_LEN = 20

# Names we never let any tier claim through the public API.
# Even admin can technically take these (via direct DB), but the API rejects.
RESERVED_USERNAMES = frozenset({
    "admin", "administrator", "root", "system", "morok", "morok_app",
    "support", "help", "abuse", "security", "official", "team",
    "anonymous", "anon", "null", "undefined", "me", "self",
    "channel", "group", "user", "users",
})


def normalize_username(raw: str) -> str:
    """
    Strip leading @, lowercase, trim whitespace.

    Order matters: strip whitespace FIRST so leading "@" is exposed,
    THEN lstrip the "@", THEN lowercase.
    """
    return raw.strip().lstrip("@").lower()


def validate_username_for_tier(username: str, tier: str) -> str:
    """
    Full validation: normalize + character check + tier-specific length +
    reserved-list check.

    Returns the normalized name on success. Raises ValueError on any
    violation — caller decides whether to surface as 400 or 403.
    """
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
    """
    Request to claim a @username. Tier check happens server-side inside
    the endpoint, NOT in this Pydantic validator — because we need the
    authenticated user's tier from the DB before we can validate length.

    So we only do the cheap, tier-independent checks here.
    """
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

        # NOTE: length-vs-tier check is done in the endpoint, not here.
        return normalized


class UserInfo(BaseModel):
    """Public information about a user — what others can see."""
    pubkey_hex: str
    username: str | None
    home_relay: str
    last_seen_at: int | None


class MeInfo(BaseModel):
    """Information about the current authenticated user."""
    pubkey_hex: str
    username: str | None
    home_relay: str
    tier: str
    created_at: int


class UsernameReleaseResponse(BaseModel):
    released: bool
    cooldown_until: int


# ============================================================================
# MESSAGE ENVELOPE
# ============================================================================

class EnvelopeIn(BaseModel):
    from_: str = Field(..., alias="from", pattern=r"^[0-9a-f]{64}$")
    to: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    ts: int = Field(..., ge=0)
    ttl: int = Field(..., ge=1, le=86400)  # max 24h — matches hard cap
    blob: str
    sig: str = Field(..., pattern=r"^[0-9a-f]{128}$")

    model_config = {"populate_by_name": True}


class EnvelopeAck(BaseModel):
    envelope_id: str
    queued: bool
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
