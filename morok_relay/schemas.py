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
    """Server returns a session token (short-lived)."""
    session_token: str
    expires_at: int


# ============================================================================
# USER & USERNAME
# ============================================================================

USERNAME_PATTERN = re.compile(r"^[a-z0-9_]{3,20}$")


class UsernameClaim(BaseModel):
    """Reserve a @username bound to caller's pubkey."""
    username: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.lower().lstrip("@").strip()
        if not USERNAME_PATTERN.match(v):
            raise ValueError(
                "Username must be 3-20 chars, lowercase letters, digits, "
                "or underscores only"
            )
        # Additional rules: cannot start with a digit, no leading underscore
        if v[0].isdigit() or v[0] == "_":
            raise ValueError("Username cannot start with digit or underscore")
        return v


class UserInfo(BaseModel):
    """Public information about a user — what others can see."""
    pubkey_hex: str
    username: str | None
    home_relay: str
    last_seen_at: int | None


# ============================================================================
# MESSAGE ENVELOPE
# ============================================================================

class EnvelopeIn(BaseModel):
    """
    A message envelope sent by a client.

    Note: this is a wire format. Crypto verification happens in crypto.py
    against the JSON dict directly (because canonical serialization rules
    must match exactly between sender and verifier).
    """
    from_: str = Field(..., alias="from", pattern=r"^[0-9a-f]{64}$")
    to: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    ts: int = Field(..., ge=0)
    ttl: int = Field(..., ge=1, le=86400)  # max 24h client-side TTL
    blob: str  # base64 encrypted payload
    sig: str = Field(..., pattern=r"^[0-9a-f]{128}$")

    model_config = {"populate_by_name": True}


class EnvelopeAck(BaseModel):
    """Acknowledgment of envelope receipt."""
    envelope_id: str
    queued: bool
    expires_at: int  # when blob will be hard-deleted regardless of delivery


# ============================================================================
# HEALTH
# ============================================================================

class HealthResponse(BaseModel):
    status: str
    relay_name: str
    version: str


# ============================================================================
# ERROR
# ============================================================================

class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: str | None = None
