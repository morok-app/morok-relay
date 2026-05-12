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
    """Client requests an auth challenge for their pubkey."""
    pubkey_hex: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class ChallengeResponse(BaseModel):
    """Server returns a fresh challenge."""
    challenge_hex: str
    expires_at: int  # epoch seconds


class AuthRequest(BaseModel):
    """Client signs the challenge and sends back."""
    pubkey_hex: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    challenge_hex: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    timestamp: int = Field(..., ge=0)
    signature_hex: str = Field(..., pattern=r"^[0-9a-f]{128}$")


class AuthResponse(BaseModel):
    """Server returns a session token (sliding TTL, 7 days)."""
    session_token: str
    expires_at: int
    pubkey_hex: str


class LogoutResponse(BaseModel):
    """Result of session revocation."""
    revoked: bool


# ============================================================================
# USER & USERNAME
# ============================================================================

USERNAME_PATTERN = re.compile(r"^[a-z0-9_]{3,20}$")
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
    Does NOT validate — just normalizes.
    """
    return raw.strip().lstrip("@").lower()


class UsernameClaim(BaseModel):
    """Reserve a @username bound to caller's pubkey."""
    username: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = normalize_username(v)
        if not USERNAME_PATTERN.match(v):
            raise ValueError(
                "Username must be 3-20 chars, lowercase letters, digits, "
                "or underscores only"
            )
        if v[0].isdigit() or v[0] == "_":
            raise ValueError("Username cannot start with digit or underscore")
        if v in RESERVED_USERNAMES:
            raise ValueError("This username is reserved")
        return v


class UserInfo(BaseModel):
    """Public information about a user — what others can see."""
    pubkey_hex: str
    username: str | None
    home_relay: str
    last_seen_at: int | None


class MeInfo(BaseModel):
    """
    Information about the current authenticated user.

    Same fields as UserInfo for now — but separate type so we can add
    private-only fields later without leaking them via `lookup`.
    """
    pubkey_hex: str
    username: str | None
    home_relay: str
    created_at: int


class UsernameReleaseResponse(BaseModel):
    """Result of releasing a username."""
    released: bool
    cooldown_until: int  # epoch seconds — others can claim after this


# ============================================================================
# MESSAGE ENVELOPE (not used yet — for future commits)
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
# HEALTH & ERROR
# ============================================================================

class HealthResponse(BaseModel):
    status: str
    relay_name: str
    version: str


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
