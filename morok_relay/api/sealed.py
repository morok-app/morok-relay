"""
Sealed Sender (фаза 1): анонімні DM-конверти.

Звичайний конверт (v1) розкриває релею метадані: ХТО кому пише, коли і
як часто — соціальний граф. Sealed-конверт (v2) цього не містить:

    зовні:    {to, ts, ttl, blob, delivery_token, delete_key_hash?}
    всередині blob (E2EE, ефемерний ключ):
              {sender, sig, payload} — перевіряє ОДЕРЖУВАЧ, не релей

Анти-спам без особи відправника — delivery tokens:
    1. Одержувач генерує секретний токен у себе на клієнті,
       реєструє тут sha256(token) — САМ токен при РЕЄСТРАЦІЇ до релея
       не доходить, клієнт хешує локально й шле лише хеш.
    2. Токен передається контактам всередині E2EE-листування.
    3. Sealed-конверт приймається лише з валідним токеном; ліміт
       рахується ПО ТОКЕНУ — релей знає "хтось із дозволених", не хто.

ТОЧНІСТЬ (аудит зовн. №4): при ВІДПРАВЦІ (крок 3) сирий токен ТАКИ
приходить у тілі запиту plaintext — це логічно необхідно, релей мусить
його отримати, щоб порахувати sha256 і звірити з зареєстрованим хешем.
Твердження "токен ніколи не бачить релей" було б неточним для цього
шляху; коректно — "релей НЕ ЗБЕРІГАЄ сирий токен, лише транзитом
хешує". Токен також довгостроковий per-contact (rate-limited, НЕ
одноразовий) — стабільний token_hash дозволяє релею пов'язати кілька
sealed-конвертів як "від одного анонімного контакту", не знаючи, хто
це. Детальніше — у README, розділ приватності.

Видалення без особи — delete keys:
    Відправник кладе в конверт sha256(k); пред'явивши k, доводить
    право на видалення, не розкриваючись.

ВАЖЛИВО: endpoint відправки НЕАВТЕНТИФІКОВАНИЙ — інакше сесія видала б
відправника. Клієнт шле sealed-конверт напряму на ДОМАШНІЙ релей
одержувача (у парі з Tor це ховає і IP). Жоден v1-шлях не змінений.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import time

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy import text as sa_text

from .. import blob_storage
from ..config import get_settings
from ..deps import CurrentSession, DBSession, RedisClient
from ..models import InboxToken, User
from ..push_sender import schedule_push
from ..queue import (
    delete_sealed_envelope,
    enqueue_envelope,
    envelope_exists,
)
from ..rate_limit import rate_limit_by_ip

logger = logging.getLogger(__name__)

router = APIRouter(tags=["sealed"])

HEX64 = r"^[0-9a-f]{64}$"

# Per-contact tokens: a user may register one delivery-token hash per
# contact. 64 is generous for a contact list while bounding storage and
# the cost of the "is this hash valid" lookup on the unauth sealed path.
MAX_TOKENS_PER_PUBKEY = 64


# ─── Реєстрація delivery-токенів (автентифіковано, бо це МІЙ інбокс) ──

class InboxTokenRegisterRequest(BaseModel):
    token_hash: str = Field(..., pattern=HEX64)


async def _fetch_inbox_tokens_for_pubkey(db, pubkey: bytes) -> list:
    """
    Винесено в окрему функцію (той самий підхід, що
    _count_push_subscriptions у api/push.py) — і для чистоти, і для
    testability: точка, потрібна тестам для синхронізації concurrency-
    race без ризикованого перехоплення AsyncSession.execute (яке
    конфліктує з SQLAlchemy async internals і дає deadlock).
    """
    return list((await db.execute(
        select(InboxToken)
        .where(InboxToken.pubkey == pubkey)
        .order_by(InboxToken.created_at.desc())
    )).scalars().all())


@router.post(
    "/inbox-token",
    summary="Register sha256 hash of my sealed-sender delivery token",
)
async def register_inbox_token(
    body: InboxTokenRegisterRequest,
    current: CurrentSession,
    db: DBSession,
) -> dict:
    """
    Per-contact delivery tokens: a user registers one token hash PER
    contact they hand a token to. The relay stores only the SET of valid
    hashes — it does NOT know which hash maps to which contact (that
    binding lives only on the client). So the relay sees "a valid hash
    was presented", never "contact X is sending".

    Cap at MAX_TOKENS_PER_PUBKEY hashes per user (plenty for a contact
    list; oldest evicted beyond that). Idempotent: re-registering an
    existing hash is a no-op.
    """
    pubkey = bytes.fromhex(current.pubkey_hex)
    now = int(time.time())

    # Атомарний check-then-evict-then-insert (жорсткий свіжий прохід —
    # той самий клас race, знайдений тим самим заходом у burner_tokens/
    # invite_tokens/push subscriptions). Тут наслідок м'якший (eviction,
    # не rejection — черговий register сам довів би кількість до норми),
    # але pg_advisory_xact_lock прибирає навіть це тимчасове перевищення
    # дешево, тим самим перевіреним підходом, що вже working для DMS/
    # mail/push квот.
    await db.execute(
        sa_text("SELECT pg_advisory_xact_lock(hashtext(:pk))"),
        {"pk": current.pubkey_hex},
    )
    rows = await _fetch_inbox_tokens_for_pubkey(db, pubkey)

    if any(r.token_hash == body.token_hash for r in rows):
        return {"registered": True, "rotated": False}

    # Evict oldest beyond the cap (keep the newest MAX-1, add the new one).
    for stale in rows[MAX_TOKENS_PER_PUBKEY - 1:]:
        await db.delete(stale)

    db.add(InboxToken(
        pubkey=pubkey,
        token_hash=body.token_hash,
        created_at=now,
    ))
    return {"registered": True, "rotated": bool(rows)}


class InboxTokenRevokeRequest(BaseModel):
    token_hash: str = Field(..., pattern=HEX64)


@router.post(
    "/inbox-token/revoke",
    summary="Revoke a single delivery-token hash (per-contact revocation)",
)
async def revoke_inbox_token(
    body: InboxTokenRevokeRequest,
    current: CurrentSession,
    db: DBSession,
) -> dict:
    """
    Remove ONE token hash. Used to cut off a single contact without
    affecting the tokens given to everyone else. The relay deletes the
    hash from the valid set; the next sealed envelope presenting it gets
    rejected (invalid_delivery_token). Idempotent.
    """
    pubkey = bytes.fromhex(current.pubkey_hex)
    await db.execute(
        delete(InboxToken)
        .where(InboxToken.pubkey == pubkey)
        .where(InboxToken.token_hash == body.token_hash)
    )
    return {"revoked": True}


# ─── Відправка sealed-конверта (БЕЗ автентифікації — це і є суть) ────

class SealedEnvelopeIn(BaseModel):
    to: str = Field(..., pattern=HEX64)
    ts: int
    ttl: int = Field(..., ge=60, le=60 * 60 * 24 * 30)
    blob: str = Field(..., min_length=1)
    delivery_token: str = Field(..., pattern=HEX64)
    delete_key_hash: str | None = Field(default=None, pattern=HEX64)


class SealedAck(BaseModel):
    envelope_id: str
    queued: bool
    expires_at: int


async def _check_token_rate_limit(redis, token_hash: str, limit: int) -> None:
    """Ліміт по токену: релей не знає ХТО, але стримує ЯК ЧАСТО."""
    key = f"morok:rl:sealed:{token_hash}"
    try:
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, 60)
        if count > limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="sealed_rate_limit_exceeded",
            )
    except HTTPException:
        raise
    except Exception as e:
        # Redis глюкнув — не валимо доставку через лімітер.
        logger.warning("sealed rate-limit check failed: %s", e)


@router.post(
    "/messages/sealed",
    response_model=SealedAck,
    summary="Submit a sealed (sender-anonymous) envelope",
    dependencies=[Depends(rate_limit_by_ip("sealed_send", 120))],
)
async def send_sealed_envelope(
    body: SealedEnvelopeIn,
    db: DBSession,
    redis: RedisClient,
) -> SealedAck:
    settings = get_settings()
    now = int(time.time())

    if body.ts < now - 300:
        raise HTTPException(status_code=400, detail="envelope_too_old")
    if body.ts > now + 60:
        raise HTTPException(status_code=400, detail="envelope_from_the_future")

    try:
        blob_bytes = base64.b64decode(body.blob, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="blob_not_base64")
    if len(blob_bytes) > settings.max_blob_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"blob_too_large_max_{settings.max_blob_bytes}_bytes",
        )

    recipient_pubkey = bytes.fromhex(body.to)
    recipient = (await db.execute(
        select(User)
        .where(User.pubkey == recipient_pubkey)
        .where(User.deleted_at.is_(None))
    )).scalar_one_or_none()

    if recipient is None:
        raise HTTPException(status_code=404, detail="recipient_unknown")
    if recipient.home_relay != settings.relay_name:
        # Sealed НЕ федерується у фазі 1: клієнт шле напряму на домашній
        # релей одержувача (він знає його з lookup). Federation-hop
        # додав би релею відправника знання "мій юзер X комусь пише".
        raise HTTPException(
            status_code=status.HTTP_421_MISDIRECTED_REQUEST,
            detail="recipient_not_local_post_to_home_relay",
        )

    # ── Delivery token: sha256(пред'явлений) ∈ зареєстровані хеші ──
    presented_hash = hashlib.sha256(
        bytes.fromhex(body.delivery_token)
    ).hexdigest()
    token_row = (await db.execute(
        select(InboxToken)
        .where(InboxToken.pubkey == recipient_pubkey)
        .where(InboxToken.token_hash == presented_hash)
    )).scalar_one_or_none()
    if token_row is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid_delivery_token",
        )

    await _check_token_rate_limit(
        redis, presented_hash, settings.rate_limit_sealed_per_minute,
    )

    # envelope_id детермінований, але БЕЗ байтів відправника
    h = hashlib.sha256()
    h.update(b"sealed.v1")
    h.update(recipient_pubkey)
    h.update(body.ts.to_bytes(8, "big"))
    h.update(hashlib.sha256(blob_bytes).digest())
    envelope_id = h.hexdigest()

    if await envelope_exists(redis, envelope_id):
        return SealedAck(envelope_id=envelope_id, queued=False, expires_at=0)

    await blob_storage.write_blob(envelope_id, blob_bytes)
    expires_at = await enqueue_envelope(
        redis=redis,
        envelope_id=envelope_id,
        sender_pubkey_hex="",          # особа — всередині blob
        recipient_pubkey_hex=body.to,
        timestamp=body.ts,
        ttl_seconds=body.ttl,
        signature_hex="",              # зовнішнього підпису немає
        hard_ceiling_seconds=settings.message_ttl_hard_seconds,
        sender_username=None,
        sealed=True,
        delete_key_hash=body.delete_key_hash,
    )
    if expires_at is None:
        return SealedAck(envelope_id=envelope_id, queued=False, expires_at=0)

    schedule_push(
        redis=redis,
        recipient_pubkeys_hex=[body.to],
        sender_username=None,      # generic push, нуль метаданих
    )

    return SealedAck(
        envelope_id=envelope_id, queued=True, expires_at=expires_at,
    )


# ─── Видалення sealed-конверта (preimage delete-ключа замість особи) ──

class SealedDeleteRequest(BaseModel):
    delete_key: str = Field(..., pattern=HEX64)


@router.post(
    "/messages/sealed/{envelope_id}/delete",
    summary="Delete a sealed envelope by presenting the delete-key preimage",
    dependencies=[Depends(rate_limit_by_ip("sealed_delete", 60))],
)
async def delete_sealed(
    envelope_id: str,
    body: SealedDeleteRequest,
    redis: RedisClient,
) -> dict:
    if len(envelope_id) != 64 or not all(
        c in "0123456789abcdef" for c in envelope_id
    ):
        raise HTTPException(status_code=400, detail="malformed_envelope_id")

    result = await delete_sealed_envelope(
        redis=redis,
        envelope_id=envelope_id,
        delete_key_hex=body.delete_key,
    )
    err = result.get("error")
    # Uniform response for every failure mode (not_found / not_sealed /
    # wrong_key): a single opaque 403 so a caller holding an envelope_id
    # can't use the status code as an oracle to learn whether the
    # envelope still exists / is sealed / had a different delete-key.
    if err is not None:
        raise HTTPException(status_code=403, detail="delete_not_authorized")

    return {"deleted": True, "envelope_id": envelope_id}
