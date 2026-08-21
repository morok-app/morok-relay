"""
Web push subscription endpoints.

The client registers a PushSubscription via the browser's PushManager API
and POSTs the result here. The relay stores (pubkey, endpoint, p256dh,
auth) tuples and uses them when fanning out a push for an incoming
message (see push_sender.trigger_push).

Subscriptions are scoped to the authenticated pubkey, so a user with
multiple devices accumulates multiple subscriptions — that's intended.
"""
from __future__ import annotations

import logging
import time
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select
from sqlalchemy import text as sa_text

from ..config import get_settings
from ..deps import CurrentSession, DBSession, RedisClient
from ..federation_client import resolve_pinned_peer
from ..models import PushSubscription
from ..rate_limit import check_rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(tags=["push"])


@router.get(
    "/vapid-public-key",
    summary="Get this relay's VAPID public key (base64url) for push subscriptions",
)
async def get_vapid_public_key() -> dict:
    settings = get_settings()
    if not settings.vapid_public_key_b64:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="push_not_configured",
        )
    return {"key": settings.vapid_public_key_b64}


class PushKeys(BaseModel):
    p256dh: str = Field(..., min_length=1, max_length=255)
    auth: str = Field(..., min_length=1, max_length=255)


# Реальні провайдери web push, з якими має справу браузерний PushManager.
# Endpoint від будь-якого іншого хоста — не «ще один провайдер», а
# довільна URL, куди relay зробить authenticated POST на наш кошт.
_ALLOWED_PUSH_HOST_SUFFIXES = (
    ".push.services.mozilla.com",
    ".notify.windows.com",
    "fcm.googleapis.com",
    "android.googleapis.com",
    "web.push.apple.com",
)


class PushSubscribeRequest(BaseModel):
    endpoint: str = Field(..., min_length=1, max_length=4096)
    keys: PushKeys
    user_agent: str | None = Field(default=None, max_length=255)

    @field_validator("endpoint")
    @classmethod
    def _endpoint_must_be_known_push_provider(cls, v: str) -> str:
        """
        Аудит зовн. №3, HIGH — authenticated SSRF + DoS-amplifier.

        endpoint приймався як довільний рядок до 4096 символів без
        перевірки схеми/host/IP. pywebpush пізніше робить на нього
        звичайний HTTP POST — тобто залогінений користувач міг змусити
        релей стукати куди завгодно, включно з внутрішньою мережею
        (blind SSRF), якщо egress окремо не відфільтрований.

        Дозволяємо ЛИШЕ https на відомі хости push-провайдерів. Це не
        рівень захисту "приблизно" — браузерний PushManager фізично не
        видає endpoint поза цим списком, тож звуження нічого легітимного
        не ламає.
        """
        try:
            parsed = urlsplit(v)
        except ValueError:
            raise ValueError("malformed endpoint URL")
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("endpoint must be an https:// URL")
        host = parsed.hostname.lower()
        if not any(
            host == suf.lstrip(".") or host.endswith(suf)
            for suf in _ALLOWED_PUSH_HOST_SUFFIXES
        ):
            raise ValueError("endpoint host is not a recognized push provider")
        return v


# Максимум підписок на акаунт. Без цього один pubkey міг накопичити
# необмежену кількість рядків (усі "легітимні" за схемою — allowlist
# перевіряє ТІЛЬКИ host, а не унікальність): кожна подальша push-подія
# фан-аутиться на весь список, отже необмежена кількість = необмежений
# амплiфікований трафік з relay на push-провайдери за одну вхідну подію.
MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT = 10


async def _count_push_subscriptions(db, pubkey: bytes) -> int:
    """
    Винесено в окрему функцію (жорсткий свіжий прохід): і для чистоти
    коду (спільний хелпер для web push + native FCM, які рахують ОДНУ
    спільну квоту), і для testability — саме ця точка потрібна тестам
    для точної синхронізації concurrency-race без ризикованого
    перехоплення AsyncSession.execute (яке конфліктує з SQLAlchemy
    async internals / greenlet-based механізмом і дає deadlock).
    """
    return (await db.execute(
        select(func.count()).select_from(PushSubscription)
        .where(PushSubscription.pubkey == pubkey)
    )).scalar_one()


@router.post(
    "/subscribe",
    summary="Register or update a web push subscription for this device",
)
async def post_subscribe(
    body: PushSubscribeRequest,
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
) -> dict:
    settings = get_settings()
    if not settings.vapid_public_key_b64:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="push_not_configured",
        )

    # Rate limit: ендпоінт раніше не мав ЖОДНОГО обмеження.
    allowed, _, retry_after = await check_rate_limit(
        redis, "push_subscribe", current.pubkey_hex, limit_per_minute=10,
    )
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="rate_limited",
            headers={"Retry-After": str(retry_after)},
        )

    pubkey = bytes.fromhex(current.pubkey_hex)
    now = int(time.time())

    stmt = (
        select(PushSubscription)
        .where(PushSubscription.pubkey == pubkey)
        .where(PushSubscription.endpoint == body.endpoint)
    )
    existing = (await db.execute(stmt)).scalar_one_or_none()

    if existing is not None:
        # Refresh keys (push services rotate them occasionally) and timestamps
        existing.p256dh = body.keys.p256dh
        existing.auth = body.keys.auth
        existing.updated_at = now
        if body.user_agent:
            existing.user_agent = body.user_agent[:255]
        await db.flush()
        return {"ok": True, "created": False}

    # Атомарний check-then-insert (жорсткий свіжий прохід — той самий
    # клас race, явно вказаний у зовн. аудиті №5: "Web Push quota
    # зроблена через COUNT → INSERT, тому під сильною concurrency сама
    # межа 10 теж не строго атомарна"). pg_advisory_xact_lock — той
    # самий перевірений підхід, що вже working для DMS quota і mail
    # quota: серіалізує конкурентні subscribe ЛИШЕ для цього pubkey.
    await db.execute(
        sa_text("SELECT pg_advisory_xact_lock(hashtext(:pk))"),
        {"pk": current.pubkey_hex},
    )
    count = await _count_push_subscriptions(db, pubkey)
    if count >= MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="too_many_push_subscriptions",
        )

    sub = PushSubscription(
        pubkey=pubkey,
        endpoint=body.endpoint,
        p256dh=body.keys.p256dh,
        auth=body.keys.auth,
        user_agent=body.user_agent[:255] if body.user_agent else None,
        created_at=now,
        updated_at=now,
    )
    db.add(sub)
    await db.flush()
    return {"ok": True, "created": True}


class PushUnsubscribeRequest(BaseModel):
    endpoint: str = Field(..., min_length=1, max_length=4096)


@router.post(
    "/unsubscribe",
    summary="Remove a push subscription for this device",
)
async def post_unsubscribe(
    body: PushUnsubscribeRequest,
    current: CurrentSession,
    db: DBSession,
) -> dict:
    pubkey = bytes.fromhex(current.pubkey_hex)
    result = await db.execute(
        delete(PushSubscription)
        .where(PushSubscription.pubkey == pubkey)
        .where(PushSubscription.endpoint == body.endpoint)
    )
    await db.flush()
    return {"ok": True, "removed": result.rowcount or 0}


# ─── Нативні (FCM) підписки ──────────────────────────────────────────

class NativePushSubscribeRequest(BaseModel):
    token: str = Field(..., min_length=10, max_length=4096)
    user_agent: str | None = Field(default=None, max_length=255)


class NativePushUnsubscribeRequest(BaseModel):
    token: str = Field(..., min_length=10, max_length=4096)


@router.post(
    "/subscribe-native",
    summary="Register or update a native (FCM) push token for this device",
)
async def post_subscribe_native(
    body: NativePushSubscribeRequest,
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
) -> dict:
    """
    Native Android push. `token` — FCM device token; зберігаємо його в
    endpoint, p256dh/auth порожні (це поля web push). Доступність FCM
    на боці релея (service account) не перевіряємо тут навмисно:
    підписка може бути зареєстрована до того, як адмін донастроїв
    relay, і запрацює без повторної реєстрації.

    Rate-limit + квота (аудит зовн. №4, MEDIUM): web push мав обидва
    захисти від самого початку, native/FCM — ні. Один спільний ліміт
    MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT рахує ОБИДВІ платформи разом
    (запит нижче навмисно без фільтра platform) — це один ресурс
    (рядки, які потім тягне push fan-out), не два окремих.
    """
    allowed, _, retry_after = await check_rate_limit(
        redis, "push_subscribe_native", current.pubkey_hex, limit_per_minute=10,
    )
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="rate_limited",
            headers={"Retry-After": str(retry_after)},
        )

    pubkey = bytes.fromhex(current.pubkey_hex)
    now = int(time.time())

    stmt = (
        select(PushSubscription)
        .where(PushSubscription.pubkey == pubkey)
        .where(PushSubscription.endpoint == body.token)
    )
    existing = (await db.execute(stmt)).scalar_one_or_none()

    if existing is not None:
        existing.platform = "fcm"
        existing.user_agent = body.user_agent
        existing.updated_at = now
        return {"subscribed": True}

    # Той самий advisory lock, що web push subscribe вище — обидва
    # шляхи рахують СПІЛЬНУ квоту (platform-агностично), тому обидва
    # мають бути серіалізовані тим самим механізмом.
    await db.execute(
        sa_text("SELECT pg_advisory_xact_lock(hashtext(:pk))"),
        {"pk": current.pubkey_hex},
    )
    count = await _count_push_subscriptions(db, pubkey)
    if count >= MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="too_many_push_subscriptions",
        )

    db.add(PushSubscription(
        pubkey=pubkey,
        endpoint=body.token,
        p256dh="",
        auth="",
        platform="fcm",
        user_agent=body.user_agent,
    ))
    return {"subscribed": True}


@router.post(
    "/unsubscribe-native",
    summary="Remove a native (FCM) push token for this device",
)
async def post_unsubscribe_native(
    body: NativePushUnsubscribeRequest,
    current: CurrentSession,
    db: DBSession,
) -> dict:
    pubkey = bytes.fromhex(current.pubkey_hex)
    await db.execute(
        delete(PushSubscription)
        .where(PushSubscription.pubkey == pubkey)
        .where(PushSubscription.endpoint == body.token)
    )
    return {"unsubscribed": True}
