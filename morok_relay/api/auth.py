"""
Authentication endpoints: challenge-response Ed25519 flow.

Rate-limited per IP because these endpoints are accessible without auth
(brute-forcing requires no session).
"""
from __future__ import annotations

import logging
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException, status

from ..config import get_settings
from ..crypto import canonical_json, ed25519_verify
from ..deps import CurrentSession, RedisClient
from ..rate_limit import rate_limit_by_ip
from ..schemas import (
    AuthRequest,
    AuthResponse,
    ChallengeRequest,
    ChallengeResponse,
    LogoutResponse,
)
from ..sessions import (
    consume_challenge,
    create_session,
    revoke_all_sessions,
    revoke_session,
    store_challenge,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])


# ============================================================================
# Endpoints (rate-limited per IP)
# ============================================================================

@router.post(
    "/challenge",
    response_model=ChallengeResponse,
    summary="Request a challenge to sign",
    dependencies=[Depends(rate_limit_by_ip(
        "auth_challenge",
        get_settings().rate_limit_auth_per_minute,
    ))],
)
async def request_challenge(
    body: ChallengeRequest,
    redis: RedisClient,
) -> ChallengeResponse:
    """Issue a one-time challenge. Client signs and POSTs to /verify."""
    challenge = secrets.token_bytes(32)
    challenge_hex = challenge.hex()
    expires_at = int(time.time()) + 60  # CHALLENGE_TTL is 60s in sessions.py

    await store_challenge(redis, challenge_hex, body.pubkey_hex)

    return ChallengeResponse(challenge_hex=challenge_hex, expires_at=expires_at)


@router.post(
    "/verify",
    response_model=AuthResponse,
    summary="Verify a signed challenge, receive session token",
    dependencies=[Depends(rate_limit_by_ip(
        "auth_verify",
        get_settings().rate_limit_auth_per_minute,
    ))],
)
async def verify_challenge(
    body: AuthRequest,
    redis: RedisClient,
) -> AuthResponse:
    """
    Verify the signed challenge, issue session token on success.

    The signature is over canonical JSON of:
        { morok_auth, challenge, pubkey, timestamp }
    """
    # Atomically read+burn the challenge — prevents replay
    expected_pubkey_hex = await consume_challenge(redis, body.challenge_hex)
    if expected_pubkey_hex is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="challenge_not_found_or_expired",
        )

    if expected_pubkey_hex != body.pubkey_hex:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="pubkey_mismatch",
        )

    # Verify timestamp window — prevents replay even if challenge was fresh.
    now = int(time.time())
    if abs(now - body.timestamp) > 120:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_signature_or_stale_timestamp",
        )

    # Verify signature
    msg = canonical_json({
        "morok_auth": "v1",
        "challenge": body.challenge_hex,
        "pubkey": body.pubkey_hex,
        "timestamp": body.timestamp,
    })
    pubkey_bytes = bytes.fromhex(body.pubkey_hex)
    sig_bytes = bytes.fromhex(body.signature_hex)
    if not ed25519_verify(msg, sig_bytes, pubkey_bytes):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_signature_or_stale_timestamp",
        )

    # Issue session — returns a Session(token, pubkey_hex, expires_at)
    session = await create_session(redis, body.pubkey_hex)

    return AuthResponse(
        session_token=session.token,
        expires_at=session.expires_at,
        pubkey_hex=session.pubkey_hex,
    )


@router.delete(
    "/session",
    response_model=LogoutResponse,
    summary="Revoke the current session token",
)
async def logout(
    current: CurrentSession,
    redis: RedisClient,
) -> LogoutResponse:
    revoked = await revoke_session(redis, current.token)
    return LogoutResponse(revoked=revoked)


@router.post(
    "/session/revoke-all",
    response_model=LogoutResponse,
    summary="Revoke ALL sessions for this pubkey (panic)",
)
async def revoke_all(
    current: CurrentSession,
    redis: RedisClient,
) -> LogoutResponse:
    count = await revoke_all_sessions(redis, current.pubkey_hex)
    logger.info(
        "Revoked %d session(s) for pubkey %s",
        count, current.pubkey_hex[:16],
    )
    return LogoutResponse(revoked=count > 0)
