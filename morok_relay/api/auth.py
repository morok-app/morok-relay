"""
Auth endpoints — Ed25519 challenge-response.

Flow
----
1. Client: POST /api/v1/auth/challenge { pubkey_hex }
   Server: returns { challenge_hex, expires_at }

2. Client: signs (challenge, pubkey, timestamp) locally, sends back:
   POST /api/v1/auth/verify { pubkey_hex, challenge_hex, timestamp, signature_hex }
   Server: verifies signature, returns { session_token, expires_at, pubkey_hex }

3. Client uses session_token in Authorization: Bearer <token> for protected endpoints.

4. Logout: DELETE /api/v1/auth/session — revokes current session token.
   POST /api/v1/auth/session/revoke-all — revokes all sessions for this pubkey.

Why challenge-response and not just "send signed payload":
- Random challenge from server makes it impossible to pre-compute or replay.
- Challenges are one-time-use (consumed on verify).
- Short TTL (60s) limits damage from any leak.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, status

from .. import crypto
from ..deps import CurrentSession, RedisClient
from ..schemas import (
    AuthRequest,
    AuthResponse,
    ChallengeRequest,
    ChallengeResponse,
    LogoutResponse,
)
from ..sessions import (
    CHALLENGE_TTL_SECONDS,
    consume_challenge,
    create_session,
    revoke_all_sessions,
    revoke_session,
    store_challenge,
)

router = APIRouter(tags=["auth"])


@router.post(
    "/challenge",
    response_model=ChallengeResponse,
    summary="Request an authentication challenge",
)
async def request_challenge(
    body: ChallengeRequest,
    redis: RedisClient,
) -> ChallengeResponse:
    """
    Get a fresh challenge to sign with your Ed25519 private key.

    The challenge is bound to your pubkey and expires in 60 seconds. Use it
    exactly once via /verify.
    """
    challenge = crypto.generate_challenge()
    challenge_hex = challenge.hex()

    await store_challenge(redis, challenge_hex, body.pubkey_hex)

    return ChallengeResponse(
        challenge_hex=challenge_hex,
        expires_at=int(time.time()) + CHALLENGE_TTL_SECONDS,
    )


@router.post(
    "/verify",
    response_model=AuthResponse,
    summary="Verify challenge signature and get a session token",
)
async def verify_challenge(
    body: AuthRequest,
    redis: RedisClient,
) -> AuthResponse:
    """
    Submit a signature over (challenge, pubkey, timestamp) to receive a session
    token.

    Returns 401 if anything is wrong: missing challenge, replay attempt,
    wrong signature, stale timestamp.
    """
    # 1. Look up + consume the challenge (atomic delete prevents reuse).
    expected_pubkey_hex = await consume_challenge(redis, body.challenge_hex)
    if expected_pubkey_hex is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="challenge_not_found_or_expired",
        )

    # 2. The pubkey requesting verification must match the one that requested
    # the challenge. Without this, anyone could intercept a challenge and try
    # to use it for a different pubkey.
    if expected_pubkey_hex != body.pubkey_hex:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="pubkey_mismatch",
        )

    # 3. Verify the signature.
    try:
        challenge_bytes = bytes.fromhex(body.challenge_hex)
        pubkey_bytes = bytes.fromhex(body.pubkey_hex)
        signature_bytes = bytes.fromhex(body.signature_hex)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_hex",
        )

    if not crypto.verify_auth_response(
        challenge=challenge_bytes,
        pubkey=pubkey_bytes,
        timestamp=body.timestamp,
        signature=signature_bytes,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_signature_or_stale_timestamp",
        )

    # 4. Mint session token.
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
    """Log out from this device only. Other sessions remain valid."""
    revoked = await revoke_session(redis, current.token)
    return LogoutResponse(revoked=revoked)


@router.post(
    "/session/revoke-all",
    response_model=LogoutResponse,
    summary="Revoke all sessions for the current user",
)
async def logout_everywhere(
    current: CurrentSession,
    redis: RedisClient,
) -> LogoutResponse:
    """
    Revoke every session for this pubkey, including the one used for this
    request.

    Used for: panic-wipe, lost device, suspected compromise.
    """
    count = await revoke_all_sessions(redis, current.pubkey_hex)
    return LogoutResponse(revoked=count > 0)
