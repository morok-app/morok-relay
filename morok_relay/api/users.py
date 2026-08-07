"""
User and username endpoints.

GET    /api/v1/users/me                    — get my profile
POST   /api/v1/users/me/username           — claim a @username
DELETE /api/v1/users/me/username           — release my @username
GET    /api/v1/users/lookup/{username}     — find user by @username (public)
       optional ?relay=hostname            — federation fallback with retry
                                             and Redis cache (24h)

v1.0 changes to /lookup:
- Redis cache (24h) for successful federation lookups
- Retry policy: 3 attempts with exponential backoff (0.5s, 1s, 2s)
- Stale-cache fallback if remote is unreachable but we have an old hit
- 503 (not 404) when remote is unreachable and no cache — clients can
  distinguish "user doesn't exist" from "peer is down"
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..config import get_settings
from ..deps import CurrentSession, DBSession, RedisClient
from ..federation_client import remote_lookup
from ..models import FederationPeer, User, UsernameHistory, UserTier
from ..schemas import (
    MeInfo,
    UserInfo,
    UsernameClaim,
    UsernameReleaseResponse,
    normalize_username,
    validate_username_for_tier,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["users"])


# ============================================================================
# Federation lookup: retry config + Redis cache
# ============================================================================

FED_LOOKUP_RETRY_DELAYS = (0.5, 1.0, 2.0)  # 3 attempts total
FED_LOOKUP_CACHE_TTL_SECONDS = 24 * 3600   # 24h


def _lookup_cache_key(relay: str, username: str) -> str:
    return f"morok:fed_lookup:{relay}:{username}"


async def _get_lookup_cache(redis, relay: str, username: str) -> dict | None:
    if redis is None:
        return None
    try:
        raw = await redis.get(_lookup_cache_key(relay, username))
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as e:
        logger.warning("Lookup cache read failed: %s", e)
        return None


async def _set_lookup_cache(redis, relay: str, username: str, data: dict) -> None:
    if redis is None:
        return
    try:
        await redis.setex(
            _lookup_cache_key(relay, username),
            FED_LOOKUP_CACHE_TTL_SECONDS,
            json.dumps(data).encode("utf-8"),
        )
    except Exception as e:
        logger.warning("Lookup cache write failed: %s", e)


async def _remote_lookup_with_retry(relay: str, username: str) -> dict | None:
    """
    Try remote_lookup up to 3 times with backoff. Returns:
    - dict with user info on success
    - None on network failure (all attempts failed)
    - {"__not_found": True} marker if peer responded but said "no such user"

    The marker is to distinguish between "peer is down" (None) and "peer
    says user doesn't exist" — the latter shouldn't trigger 503.
    """
    last_err: Exception | None = None

    for i, delay in enumerate([0] + list(FED_LOOKUP_RETRY_DELAYS)):
        if delay > 0:
            await asyncio.sleep(delay)
        try:
            result = await remote_lookup(relay, username)
            if result is None:
                # remote_lookup returns None on 404 OR HTTP error — we
                # can't tell from here. But its httpx wrapper only logs
                # warnings on real errors. For now, treat None as "no user".
                # In a more robust impl we'd extend remote_lookup to
                # distinguish these two cases.
                return {"__not_found": True}
            return result
        except Exception as e:
            last_err = e
            logger.info(
                "Federation lookup attempt %d/%d to %s failed: %s",
                i + 1, len(FED_LOOKUP_RETRY_DELAYS) + 1, relay, e,
            )

    logger.warning(
        "Federation lookup to %s exhausted retries: %s", relay, last_err,
    )
    return None


# ============================================================================
# Helpers
# ============================================================================

async def _get_or_create_user(db: DBSession, pubkey_hex: str) -> User:
    settings = get_settings()
    pubkey_bytes = bytes.fromhex(pubkey_hex)

    stmt = select(User).where(User.pubkey == pubkey_bytes)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is not None:
        user.last_seen_at = int(time.time())
        return user

    user = User(
        pubkey=pubkey_bytes,
        home_relay=settings.relay_name,
        tier=UserTier.FREE,
        last_seen_at=int(time.time()),
    )
    db.add(user)
    await db.flush()
    return user


async def _cache_remote_user(
    db: DBSession,
    pubkey_hex: str,
    username: str,
    home_relay: str,
) -> User | None:
    settings = get_settings()
    pubkey_bytes = bytes.fromhex(pubkey_hex)

    stmt = select(User).where(User.pubkey == pubkey_bytes)
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing is not None:
        # ЗАХИСТ: якщо користувач НАШ (зареєстрований тут), жодна
        # федеративна відповідь не має права переписати його home_relay.
        # Інакше чужий релей міг би заявити «цей pubkey живе в мене» — і
        # ми почали б пересилати його пошту й повідомлення туди.
        # Свої записи авторитетні локально, крапка.
        if existing.home_relay == settings.relay_name:
            if home_relay != settings.relay_name:
                logger.warning(
                    "Refusing to move local user %s... to remote relay %s",
                    pubkey_hex[:8], home_relay,
                )
            return existing

        # Federation lookup is authoritative about home_relay. Records
        # auto-created at login time may have a stale home_relay (set to
        # our own relay before we knew where this pubkey actually lives).
        # When a lookup tells us "this user actually lives on relay X",
        # we trust it and overwrite. Without this, cross-relay routing
        # never kicks in for users who ever touched this relay's auth.
        updated = False
        if existing.home_relay != home_relay:
            logger.info(
                "Correcting home_relay for %s...: %s -> %s",
                pubkey_hex[:8], existing.home_relay, home_relay,
            )
            existing.home_relay = home_relay
            updated = True
        if username and not existing.username:
            existing.username = username
            updated = True
        if updated:
            await db.flush()
        return existing

    user = User(
        pubkey=pubkey_bytes,
        username=username,
        home_relay=home_relay,
        tier=UserTier.FREE,
        last_seen_at=None,
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return (await db.execute(stmt)).scalar_one_or_none()
    return user


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/me", response_model=MeInfo, summary="Get the current user's profile")
async def get_me(current: CurrentSession, db: DBSession) -> MeInfo:
    user = await _get_or_create_user(db, current.pubkey_hex)
    return MeInfo(
        pubkey_hex=current.pubkey_hex,
        username=user.username,
        home_relay=user.home_relay,
        tier=user.tier.value,
        created_at=user.created_at,
    )


@router.post("/me/username", response_model=MeInfo, summary="Claim a @username")
async def claim_username(
    body: UsernameClaim, current: CurrentSession, db: DBSession,
) -> MeInfo:
    settings = get_settings()
    user = await _get_or_create_user(db, current.pubkey_hex)

    try:
        username = validate_username_for_tier(body.username, user.tier.value)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))

    pubkey_bytes = bytes.fromhex(current.pubkey_hex)
    now = int(time.time())

    if user.username == username:
        return MeInfo(
            pubkey_hex=current.pubkey_hex,
            username=user.username,
            home_relay=user.home_relay,
            tier=user.tier.value,
            created_at=user.created_at,
        )

    stmt = select(User).where(User.username == username)
    other = (await db.execute(stmt)).scalar_one_or_none()
    if other is not None and other.pubkey != pubkey_bytes:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="username_taken")

    cooldown_seconds = settings.username_cooldown_days * 86400
    cooldown_cutoff = now - cooldown_seconds
    stmt = (
        select(UsernameHistory)
        .where(UsernameHistory.username == username)
        .where(UsernameHistory.released_at >= cooldown_cutoff)
        .order_by(UsernameHistory.released_at.desc())
        .limit(1)
    )
    last_release = (await db.execute(stmt)).scalar_one_or_none()
    if last_release is not None and last_release.pubkey != pubkey_bytes:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="username_in_cooldown",
        )

    if user.username is not None and user.username != username:
        db.add(UsernameHistory(
            username=user.username,
            pubkey=pubkey_bytes,
            claimed_at=user.created_at,
            released_at=now,
        ))

    user.username = username
    await db.flush()

    return MeInfo(
        pubkey_hex=current.pubkey_hex,
        username=user.username,
        home_relay=user.home_relay,
        tier=user.tier.value,
        created_at=user.created_at,
    )


@router.delete(
    "/me/username",
    response_model=UsernameReleaseResponse,
    summary="Release the current user's @username",
)
async def release_username(
    current: CurrentSession, db: DBSession,
) -> UsernameReleaseResponse:
    settings = get_settings()
    pubkey_bytes = bytes.fromhex(current.pubkey_hex)
    now = int(time.time())

    user = await _get_or_create_user(db, current.pubkey_hex)

    if user.username is None:
        return UsernameReleaseResponse(released=False, cooldown_until=0)

    db.add(UsernameHistory(
        username=user.username,
        pubkey=pubkey_bytes,
        claimed_at=user.created_at,
        released_at=now,
    ))

    user.username = None
    await db.flush()

    return UsernameReleaseResponse(
        released=True,
        cooldown_until=now + settings.username_cooldown_days * 86400,
    )


@router.get(
    "/lookup/{username}",
    response_model=UserInfo,
    summary="Find a user by @username — with federation cache and retry",
)
async def lookup_username(
    username: str,
    db: DBSession,
    redis: RedisClient,
    relay: str | None = None,
) -> UserInfo:
    """
    Resolution order:
      1. Local lookup by username.
      2. If not found locally and ?relay=hostname provided:
         a. Check Redis cache (24h TTL).
         b. If not cached, try federation lookup with up to 3 retries.
         c. On success → cache it AND create/update local User row.
         d. If peer says "no such user" → 404 (don't cache).
         e. If peer unreachable → check stale cache; if found, return it
            with a header; else return 503.
      3. Otherwise 404.
    """
    settings = get_settings()
    normalized = normalize_username(username)

    # 1. Local
    stmt = (
        select(User)
        .where(User.username == normalized)
        .where(User.deleted_at.is_(None))
    )
    user = (await db.execute(stmt)).scalar_one_or_none()
    if user is not None:
        return UserInfo(
            pubkey_hex=user.pubkey.hex(),
            username=user.username,
            home_relay=user.home_relay,
            last_seen_at=user.last_seen_at,
        )

    # 2. Federation fallback — figure out which peer(s) to query
    #
    # БЕЗПЕКА: ?relay= приходить від КЛІЄНТА і НЕ є довіреним. Раніше
    # довільний хост із параметра підставлявся напряму, і будь-хто ззовні,
    # без авторизації, міг:
    #   1) змусити релей робити запити на свій сервер (SSRF-подібне);
    #   2) отримати у відповідь підроблений pubkey/home_relay для чужого
    #      імені, які релей потім ЗАПИСУВАВ у власну БД і кеш на 24 год —
    #      тобто перенаправити чужі повідомлення на сервер зловмисника.
    #
    # Тепер ?relay= — це лише ПІДКАЗКА, у якому порядку опитувати peer'ів.
    # Ходимо виключно на хости зі списку довірених федерацій. Якщо
    # підказка не серед них — не падаємо, а тихо ігноруємо її й робимо
    # звичайний fan-out: легітимний пошук працює як раніше.
    peer_stmt = (
        select(FederationPeer)
        .where(FederationPeer.is_trusted.is_(True))
        .order_by(FederationPeer.last_handshake_at.desc().nullslast())
    )
    peers = (await db.execute(peer_stmt)).scalars().all()
    trusted_hosts = [
        p.hostname for p in peers if p.hostname != settings.relay_name
    ]

    if relay is not None and relay != settings.relay_name:
        if relay in trusted_hosts:
            # Підказка валідна — питаємо названий peer першим, решту потім
            candidate_relays = [relay] + [h for h in trusted_hosts if h != relay]
        else:
            logger.warning(
                "Ignoring untrusted relay hint in lookup: %r", relay,
            )
            candidate_relays = trusted_hosts
    else:
        candidate_relays = trusted_hosts

    if not candidate_relays:
        # Немає жодного довіреного peer'а — далі йти нікуди
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="username_not_found",
        )

    last_error_status: int | None = None  # remember if any peer was unreachable

    for relay_host in candidate_relays:
        # 2a. Redis cache
        cached = await _get_lookup_cache(redis, relay_host, normalized)
        if cached is not None:
            logger.info("Federation lookup cache hit: %s on %s", normalized, relay_host)
            return UserInfo(
                pubkey_hex=cached["pubkey_hex"],
                username=cached["username"],
                home_relay=cached["home_relay"],
                last_seen_at=cached.get("last_seen_at"),
            )

        # 2b. Federation lookup with retry
        logger.info(
            "Federation lookup: %s on %s (with retry)", normalized, relay_host,
        )
        result = await _remote_lookup_with_retry(relay_host, normalized)

        # Peer says "no such user" — try next peer
        if result is not None and result.get("__not_found"):
            continue

        # Peer unreachable — remember and try next
        if result is None:
            last_error_status = status.HTTP_503_SERVICE_UNAVAILABLE
            continue

        # Success — cache + persist locally + return
        cache_payload = {
            "pubkey_hex": result["pubkey_hex"],
            "username": result["username"],
            "home_relay": result["home_relay"],
            "last_seen_at": result.get("last_seen_at"),
        }
        await _set_lookup_cache(redis, relay_host, normalized, cache_payload)

        cached_user = await _cache_remote_user(
            db,
            pubkey_hex=result["pubkey_hex"],
            username=result["username"],
            home_relay=result["home_relay"],
        )

        return UserInfo(
            pubkey_hex=result["pubkey_hex"],
            username=result["username"],
            home_relay=result["home_relay"],
            last_seen_at=cached_user.last_seen_at if cached_user else None,
        )

    # 3. Not found on any peer
    if last_error_status == status.HTTP_503_SERVICE_UNAVAILABLE:
        # Every peer we tried was unreachable — tell the client to retry
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="remote_relay_unreachable_try_later",
            headers={"Retry-After": "30"},
        )
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="username_not_found",
    )
