"""
Burner inbox endpoints.

Auth-required endpoints (owner side):
    POST   /api/v1/burner                      — create a new token
    GET    /api/v1/burner                      — list my active tokens
    DELETE /api/v1/burner/{token}              — revoke a token

Public endpoints (anonymous sender side, NO auth):
    GET    /api/v1/burner/public/{token}       — fetch owner's pubkey
                                                  (so client can encrypt for them)
    POST   /api/v1/burner/public/{token}/send  — submit an encrypted message

Rate limits:
    - POST /api/v1/burner — 5/min per pubkey (owner) to prevent token spam
    - POST /api/v1/burner/public/{token}/send — 10/min per token+IP combo
      (handled in-router, IP-based for unauth)
"""
from __future__ import annotations

import base64
import hashlib
import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select

from .. import blob_storage, burner_tokens
from ..config import get_settings
from ..deps import CurrentSession, DBSession, RedisClient
from ..models import User
from ..queue import enqueue_envelope, envelope_exists
from ..rate_limit import rate_limit_by_pubkey
from ..schemas import (
    BurnerCreate,
    BurnerInfo,
    BurnerList,
    BurnerPublicInfo,
    BurnerSend,
    BurnerSendAck,
    BurnerTokenRevoked,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["burner"])

# Anti-spam: rate limit per (burner token, client IP) for the public
# send endpoint.
#
# ДВА БАГИ, ЯКІ ТУТ БУЛИ (обидва перетворювали ліміт на глобальний DoS):
#
#   1. Ключ не містив токена, тож усі burner-скриньки релея ділили один
#      бакет: 10 повідомлень/хв НА ВЕСЬ СЕРВЕР.
#   2. IP брався з request.client.host, а за nginx це завжди 127.0.0.1 —
#      тобто «per-IP» ліміт узагалі не розрізняв клієнтів, і будь-хто,
#      хто шле 10 запитів/хв, глушив анонімні листи для всіх інших.
#
# Тепер: get_ip_from_request (довіряє forwarded-заголовкам лише від
# trusted proxy) + хеш токена. Хеш, а не сам токен, щоб секрет не
# осідав у Redis-ключах.
_send_rl_key = "morok:burner_send_rl:{token_hash}:{ip}"
SEND_RATE_LIMIT_PER_MINUTE = 10


async def _enforce_public_send_rate_limit(redis, request: Request, token: str):
    """
    Sliding-window: count send attempts per (token, IP) in the last 60s.
    """
    from ..rate_limit import get_ip_from_request

    ip = get_ip_from_request(request)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]
    key = _send_rl_key.format(token_hash=token_hash, ip=ip)
    now = int(time.time())
    bucket = key + f":{now // 60}"
    count = await redis.incr(bucket)
    if count == 1:
        await redis.expire(bucket, 90)
    if count > SEND_RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too_many_send_attempts_try_later",
            headers={"Retry-After": "60"},
        )


# ─────────────────────────────────────────────────────────────────────
# Auth-required (owner) endpoints
# ─────────────────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=BurnerInfo,
    status_code=status.HTTP_201_CREATED,
    summary="Create a burner token (anonymous inbox link)",
    dependencies=[Depends(rate_limit_by_pubkey(
        "burner_create",
        5,
    ))],
)
async def create_burner_token(
    body: BurnerCreate,
    current: CurrentSession,
    redis: RedisClient,
) -> BurnerInfo:
    active = await burner_tokens.count_active_tokens(redis, current.pubkey_hex)
    if active >= burner_tokens.MAX_ACTIVE_TOKENS_PER_OWNER:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"too_many_active_burner_links_max_{burner_tokens.MAX_ACTIVE_TOKENS_PER_OWNER}",
        )

    ttl = body.ttl_seconds or burner_tokens.DEFAULT_TTL_SECONDS
    info = await burner_tokens.create_token(
        redis,
        owner_pubkey_hex=current.pubkey_hex,
        ttl_seconds=ttl,
        label=body.label,
    )
    return BurnerInfo(**info)


@router.get(
    "",
    response_model=BurnerList,
    summary="List my active burner tokens",
)
async def list_burner_tokens(
    current: CurrentSession,
    redis: RedisClient,
) -> BurnerList:
    raw = await burner_tokens.list_tokens_for_owner(redis, current.pubkey_hex)
    return BurnerList(tokens=[BurnerInfo(**t) for t in raw])


@router.delete(
    "/{token}",
    response_model=BurnerTokenRevoked,
    summary="Revoke a burner token",
)
async def revoke_burner_token(
    token: str,
    current: CurrentSession,
    redis: RedisClient,
) -> BurnerTokenRevoked:
    if not burner_tokens.BURNER_TOKEN_PATTERN.match(token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_token",
        )
    # Verify caller owns this token
    meta = await burner_tokens.get_token(redis, token)
    if meta is None:
        return BurnerTokenRevoked(token=token, revoked=False)
    if meta.get("owner_pubkey") != current.pubkey_hex:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="not_your_token",
        )
    revoked = await burner_tokens.revoke_token(
        redis, current.pubkey_hex, token,
    )
    return BurnerTokenRevoked(token=token, revoked=revoked)


# ─────────────────────────────────────────────────────────────────────
# PUBLIC endpoints (no auth) — used by the burner-send web form
# ─────────────────────────────────────────────────────────────────────

@router.get(
    "/public/{token}",
    response_model=BurnerPublicInfo,
    summary="Get owner pubkey for a burner token (public, no auth)",
)
async def public_burner_info(
    token: str,
    redis: RedisClient,
) -> BurnerPublicInfo:
    if not burner_tokens.BURNER_TOKEN_PATTERN.match(token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_token",
        )
    meta = await burner_tokens.get_token(redis, token)
    if meta is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="burner_link_invalid_or_expired",
        )
    return BurnerPublicInfo(
        owner_pubkey_hex=meta["owner_pubkey"],
        label=meta.get("label"),
        expires_at=meta["expires_at"],
    )


@router.post(
    "/public/{token}/send",
    response_model=BurnerSendAck,
    summary="Submit an encrypted message via a burner link (public, no auth)",
)
async def public_burner_send(
    token: str,
    body: BurnerSend,
    request: Request,
    redis: RedisClient,
    db: DBSession,
) -> BurnerSendAck:
    settings = get_settings()
    if not burner_tokens.BURNER_TOKEN_PATTERN.match(token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_token",
        )

    await _enforce_public_send_rate_limit(redis, request, token)

    meta = await burner_tokens.get_token(redis, token)
    if meta is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="burner_link_invalid_or_expired",
        )

    owner_pubkey_hex = meta["owner_pubkey"]

    # Validate ephemeral pubkey format
    if len(body.ephemeral_pubkey_hex) != 64 or not all(
        c in "0123456789abcdef" for c in body.ephemeral_pubkey_hex
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_ephemeral_pubkey",
        )

    # Verify recipient (owner) exists on this relay
    owner_pubkey_bytes = bytes.fromhex(owner_pubkey_hex)
    stmt = (
        select(User)
        .where(User.pubkey == owner_pubkey_bytes)
        .where(User.deleted_at.is_(None))
    )
    recipient = (await db.execute(stmt)).scalar_one_or_none()
    if recipient is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="recipient_not_found",
        )

    # Decode blob
    try:
        blob_bytes = base64.b64decode(body.blob_b64, validate=True)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="blob_not_base64",
        )
    if len(blob_bytes) == 0 or len(blob_bytes) > settings.max_blob_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="blob_size_invalid",
        )

    # Update message count + check ceiling
    allowed, count = await burner_tokens.increment_message_count(redis, token)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="burner_link_message_limit_reached",
        )

    now = int(time.time())
    ttl_seconds = 7 * 86400  # burner messages live up to 7 days in inbox

    # Compute deterministic envelope_id (for dedup)
    h = hashlib.sha256()
    h.update(bytes.fromhex(body.ephemeral_pubkey_hex))
    h.update(owner_pubkey_bytes)
    h.update(now.to_bytes(8, "big"))
    h.update(hashlib.sha256(blob_bytes).digest())
    envelope_id = h.hexdigest()

    if await envelope_exists(redis, envelope_id):
        return BurnerSendAck(envelope_id=envelope_id, queued=False)

    await blob_storage.write_blob(envelope_id, blob_bytes)

    # Sender username metadata: we set a special "🔥 burner" so the
    # owner's client can render a badge. We also put the user-supplied
    # sender_label (if any) inside the envelope metadata via a special
    # key — but the queue.enqueue_envelope only supports sender_username,
    # so we cram both in there. The client splits on "::" to extract.
    sender_label = (body.sender_label or "").strip()[:burner_tokens.MAX_SENDER_LABEL_LEN]
    if sender_label:
        sender_meta = f"🔥burner::{sender_label}"
    else:
        sender_meta = "🔥burner"

    # Placeholder signature — the recipient client knows that messages from
    # ephemeral keys via burner links don't have verifiable sigs. The
    # 'from' field still serves as the X25519 pubkey for DH so decryption
    # works normally.
    placeholder_sig = "00" * 64

    expires_at = await enqueue_envelope(
        redis=redis,
        envelope_id=envelope_id,
        sender_pubkey_hex=body.ephemeral_pubkey_hex,
        recipient_pubkey_hex=owner_pubkey_hex,
        timestamp=now,
        ttl_seconds=ttl_seconds,
        signature_hex=placeholder_sig,
        hard_ceiling_seconds=settings.message_ttl_hard_seconds,
        sender_username=sender_meta,
    )

    logger.info(
        "Burner send: token=%s... owner=%s... count=%d",
        token[:8], owner_pubkey_hex[:16], count,
    )

    return BurnerSendAck(
        envelope_id=envelope_id,
        queued=True,
        expires_at=expires_at,
        message_count=count,
    )
