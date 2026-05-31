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

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select

from ..config import get_settings
from ..deps import CurrentSession, DBSession
from ..models import PushSubscription

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


class PushSubscribeRequest(BaseModel):
    endpoint: str = Field(..., min_length=1, max_length=4096)
    keys: PushKeys
    user_agent: str | None = Field(default=None, max_length=255)


@router.post(
    "/subscribe",
    summary="Register or update a web push subscription for this device",
)
async def post_subscribe(
    body: PushSubscribeRequest,
    current: CurrentSession,
    db: DBSession,
) -> dict:
    settings = get_settings()
    if not settings.vapid_public_key_b64:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="push_not_configured",
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
