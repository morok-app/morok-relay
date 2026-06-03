"""
Authentication endpoints: challenge-response Ed25519 flow.

Rate-limited per IP because these endpoints are accessible without auth
(brute-forcing requires no session).
"""
from __future__ import annotations

import datetime
import hashlib
import logging
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import delete, select

from ..config import get_settings
from ..crypto import canonical_json, ed25519_verify
from ..deps import CurrentSession, DBSession, RedisClient
from ..models import LoginLog
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


def _daily_ip_hash(ip: str) -> str:
    """
    Privacy-preserving fingerprint of a client IP.

    Hashes (relay_privkey || YYYY-MM-DD UTC || ip). The date component
    means the same IP yields different hashes after midnight UTC, so
    long-term cross-referencing is impossible from the DB alone. The
    relay_privkey component means anyone who only has DB dumps (no
    relay key) can't even rainbow-table the day's IPv4 space.

    If the relay's private key is not configured, falls back to date-only
    salt and logs a warning — the audit log still works but is less
    resistant to dictionary attacks if the DB leaks.
    """
    settings = get_settings()
    date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    try:
        privkey = bytes.fromhex(settings.relay_privkey_hex or "")
    except ValueError:
        privkey = b""
    if not privkey:
        # Logged once on first call per process — repeated warnings would
        # spam the log on every login.
        if not getattr(_daily_ip_hash, "_warned", False):
            logger.warning(
                "MOROK_RELAY_PRIVKEY_HEX is empty — login_log.ip_hash uses "
                "date-only salt (weaker against rainbow tables on DB leak)."
            )
            _daily_ip_hash._warned = True  # type: ignore[attr-defined]
    salt = hashlib.sha256(privkey + date_str.encode("ascii")).digest()
    return hashlib.sha256(salt + ip.encode("utf-8", errors="replace")).hexdigest()


def _extract_client_ip(request: Request) -> str:
    """
    Best-effort client IP extraction. We sit behind nginx which sets
    X-Forwarded-For; the leftmost entry is the real client.
    """
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _record_login(
    db: DBSession,
    pubkey_hex: str,
    ip: str,
    user_agent: str | None,
) -> None:
    """
    Insert a login event, then prune rows older than the 30 most recent
    for this pubkey. Best-effort — any failure is logged and swallowed
    so it never blocks the auth flow.
    """
    try:
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        ua = (user_agent or "")[:255] or None
        entry = LoginLog(
            pubkey=pubkey_bytes,
            created_at=int(time.time()),
            ip_hash=_daily_ip_hash(ip),
            user_agent=ua,
        )
        db.add(entry)
        await db.flush()

        # Prune to last 30 — delete anything older than the 30th row.
        keep_stmt = (
            select(LoginLog.id)
            .where(LoginLog.pubkey == pubkey_bytes)
            .order_by(LoginLog.created_at.desc())
            .limit(30)
        )
        keep_ids = (await db.execute(keep_stmt)).scalars().all()
        if keep_ids:
            await db.execute(
                delete(LoginLog)
                .where(LoginLog.pubkey == pubkey_bytes)
                .where(LoginLog.id.notin_(keep_ids))
            )
            await db.flush()
    except Exception as e:
        logger.warning("Failed to record login_log entry: %s", e)


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
    db: DBSession,
    request: Request,
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

    # Audit log: record this successful login. Best-effort, doesn't fail auth.
    client_ip = _extract_client_ip(request)
    user_agent = request.headers.get("user-agent")
    await _record_login(db, body.pubkey_hex, client_ip, user_agent)

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
