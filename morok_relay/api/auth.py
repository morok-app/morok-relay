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
from sqlalchemy import delete, select, update

from ..config import get_settings
from ..crypto import canonical_json, ed25519_verify
from ..deps import CurrentSession, DBSession, RedisClient
from ..models import LoginLog, User
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


async def _daily_ip_hash(redis, ip: str) -> str:
    """
    Privacy-preserving fingerprint of a client IP.

    ЕФЕМЕРНА добова сіль (аудит зовн. №2): попередня схема рахувала
    сіль як SHA256(relay_privkey || дата) — детерміновано. Це чудово
    захищало від «вкрали лише дамп БД», але НЕ від ретроспективної
    компрометації сервера: маючи privkey, можна через рік відтворити
    сіль за будь-яку дату з login-рядка й перебрати IPv4-простір.

    Тепер сіль — випадкові 32 байти, які генеруються на перший вхід
    доби (SET NX) і живуть у Redis 48 годин. Після протухання сіль
    фізично зникає, і хеші за минулі дні стають незворотними ДЛЯ ВСІХ,
    включно з нами: навіть повна компрометація сервера відкриває
    щонайбільше сьогодні і вчора.

    Групування в межах доби (навіщо хеш узагалі існує — «5 входів з
    однієї адреси сьогодні») працює як і раніше.

    Fallback при недоступному Redis: детермінована сіль від privkey —
    стара схема, гірша за нову, але краща за відсутність журналу.
    """
    date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    salt_key = f"morok:login_salt:{date_str}"

    salt: bytes | None = None
    try:
        candidate = secrets.token_bytes(32)
        # SET NX: перший запит доби кладе свою сіль, решта читає її ж.
        was_set = await redis.set(salt_key, candidate, nx=True, ex=48 * 3600)
        salt = candidate if was_set else await redis.get(salt_key)
    except Exception as e:
        if not getattr(_daily_ip_hash, "_warned_redis", False):
            logger.warning(
                "login_salt unavailable in Redis (%s) — falling back to "
                "deterministic salt (weaker retrospective privacy)", e,
            )
            _daily_ip_hash._warned_redis = True  # type: ignore[attr-defined]

    if not salt:
        settings = get_settings()
        try:
            privkey = bytes.fromhex(settings.relay_privkey_hex or "")
        except ValueError:
            privkey = b""
        salt = hashlib.sha256(privkey + date_str.encode("ascii")).digest()

    return hashlib.sha256(salt + ip.encode("utf-8", errors="replace")).hexdigest()


def _extract_client_ip(request: Request) -> str:
    """
    Client IP for the login audit log. Delegates to the hardened
    rate_limit.get_ip_from_request, which only trusts forwarded headers
    from configured trusted proxies — so a direct connection past nginx
    can't spoof the IP recorded in login_log.
    """
    from ..rate_limit import get_ip_from_request
    return get_ip_from_request(request)


async def _reactivate_if_deleted(db: DBSession, pubkey_hex: str) -> bool:
    """
    Успішний вхід знімає позначку видалення, якщо вона стояла.

    СЕМАНТИКА ВИДАЛЕННЯ: «видалити акаунт» = стерти дані на сервері
    (звільнити username, знести бекапи, push-підписки, заповіти) і
    відкликати сесії. Це НЕ надгробок на ключі.

    Чому саме так. Особа в Morok — це пара ключів, згенерована на
    пристрої; релей її не видає і не може «заборонити». Хто завгодно
    робить нову мнемоніку за десять секунд, тож вічна заборона не
    заважає зловмиснику взагалі, а карає лише того, хто передумав і
    відновився зі старої фрази. Гірше: без цього виклику така людина
    отримувала б акаунт, що мовчки поводиться як напів-видалений —
    найнеприємніший клас багів, бо виглядає як поломка, а не як задум.

    Повертається саме ПОРОЖНІЙ акаунт: username уже звільнено при
    видаленні й міг бути зайнятий іншим, дані стерті. Тобто це
    реєстрація наново тим самим ключем.

    Best-effort, як і _record_login: збій тут не має валити вхід. У
    найгіршому разі поведінка лишається такою, як була до цього патчу.
    """
    try:
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        stmt = (
            update(User)
            .where(User.pubkey == pubkey_bytes)
            .where(User.deleted_at.is_not(None))
            .values(deleted_at=None, last_seen_at=int(time.time()))
        )
        result = await db.execute(stmt)
        if result.rowcount:
            logger.info(
                "Reactivated previously deleted account %s on login",
                pubkey_hex[:8],
            )
            return True
        return False
    except Exception as e:
        logger.warning("Reactivate-on-login failed for %s: %s", pubkey_hex[:8], e)
        return False


async def _record_login(
    db: DBSession,
    redis,
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
            ip_hash=await _daily_ip_hash(redis, ip),
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

    # Якщо акаунт був позначений видаленим — вхід тим самим ключем
    # знімає позначку (див. _reactivate_if_deleted). Робимо ДО видачі
    # сесії, щоб не лишалося вікна «сесія є, а рядок ще видалений».
    await _reactivate_if_deleted(db, body.pubkey_hex)

    # Issue session — returns a Session(token, pubkey_hex, expires_at)
    session = await create_session(redis, body.pubkey_hex)

    # Audit log: record this successful login. Best-effort, doesn't fail auth.
    client_ip = _extract_client_ip(request)
    user_agent = request.headers.get("user-agent")
    await _record_login(db, redis, body.pubkey_hex, client_ip, user_agent)

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
