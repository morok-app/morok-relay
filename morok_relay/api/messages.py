"""
Direct (1-on-1) message endpoints.

Rate-limited per pubkey on the POST endpoint to prevent message-spam attacks.
GET/DELETE are not limited — they only touch caller's own inbox.

Federation routing:
- If the recipient User row has home_relay = settings.relay_name → local enqueue
- If home_relay points to a different relay → outbound federation queue
- If the recipient is not in our users table at all → 404
  (clients must call /users/lookup with ?relay= first to cache the user)
"""
from __future__ import annotations

import base64
import hashlib
import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select

from .. import blob_storage, crypto
from ..config import get_settings
from ..deps import CurrentSession, DBSession, RedisClient
from ..models import FederationOutboundQueue, FedQueueStatus, User
from ..queue import (
    acknowledge_envelope,
    enqueue_envelope,
    envelope_exists,
    list_inbox,
)
from ..rate_limit import rate_limit_by_pubkey
from ..schemas import EnvelopeAck, EnvelopeIn

logger = logging.getLogger(__name__)

router = APIRouter(tags=["messages"])


@router.post(
    "",
    response_model=EnvelopeAck,
    summary="Submit an encrypted envelope for delivery (local or federated)",
    dependencies=[Depends(rate_limit_by_pubkey(
        "messages_send",
        get_settings().rate_limit_messages_per_minute,
    ))],
)
async def send_envelope(
    body: EnvelopeIn,
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
) -> EnvelopeAck:
    settings = get_settings()

    if body.from_ != current.pubkey_hex:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="from_field_must_match_authenticated_pubkey",
        )

    sender_pubkey = bytes.fromhex(current.pubkey_hex)
    recipient_pubkey = bytes.fromhex(body.to)

    # Verify signature
    unsigned = {
        "from": body.from_, "to": body.to,
        "ts": body.ts, "ttl": body.ttl, "blob": body.blob,
    }
    canonical = crypto.canonical_json(unsigned)
    try:
        sig_bytes = bytes.fromhex(body.sig)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_sig_hex",
        )
    if not crypto.ed25519_verify(canonical, sig_bytes, sender_pubkey):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="signature_invalid",
        )

    now = int(time.time())
    if body.ts < now - 300:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="envelope_too_old",
        )
    if body.ts > now + 60:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="envelope_from_the_future",
        )

    try:
        blob_bytes = base64.b64decode(body.blob, validate=True)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="blob_not_base64",
        )
    if len(blob_bytes) > settings.max_blob_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"blob_too_large_max_{settings.max_blob_bytes}_bytes",
        )

    # Compute envelope_id (deterministic — used for dedup)
    h = hashlib.sha256()
    h.update(sender_pubkey)
    h.update(recipient_pubkey)
    h.update(body.ts.to_bytes(8, "big"))
    h.update(hashlib.sha256(blob_bytes).digest())
    envelope_id = h.hexdigest()

    # Look up recipient — we need home_relay to decide routing
    stmt = (
        select(User)
        .where(User.pubkey == recipient_pubkey)
        .where(User.deleted_at.is_(None))
    )
    recipient = (await db.execute(stmt)).scalar_one_or_none()

    if recipient is None:
        # We don't know this pubkey. Client must lookup first
        # (so we learn the home_relay and cache it).
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="recipient_unknown_call_lookup_first",
        )

    # ---- LOCAL DELIVERY ----
    if recipient.home_relay == settings.relay_name:
        if await envelope_exists(redis, envelope_id):
            return EnvelopeAck(envelope_id=envelope_id, queued=False, expires_at=0)

        await blob_storage.write_blob(envelope_id, blob_bytes)
        expires_at = await enqueue_envelope(
            redis=redis,
            envelope_id=envelope_id,
            sender_pubkey_hex=body.from_,
            recipient_pubkey_hex=body.to,
            timestamp=body.ts,
            ttl_seconds=body.ttl,
            signature_hex=body.sig,
            hard_ceiling_seconds=settings.message_ttl_hard_seconds,
        )
        return EnvelopeAck(
            envelope_id=envelope_id, queued=True, expires_at=expires_at,
        )

    # ---- FEDERATION DELIVERY ----
    # Dedup against the outbound queue too
    stmt = (
        select(FederationOutboundQueue)
        .where(FederationOutboundQueue.envelope_id == envelope_id)
        .limit(1)
    )
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing is not None:
        return EnvelopeAck(envelope_id=envelope_id, queued=False, expires_at=0)

    envelope_dict = {
        "from": body.from_,
        "to": body.to,
        "ts": body.ts,
        "ttl": body.ttl,
        "blob": body.blob,
        "sig": body.sig,
    }

    # Cap expiry at the hard ceiling (worker will refuse to send if expired)
    requested_expires = body.ts + body.ttl
    ceiling = now + settings.message_ttl_hard_seconds
    expires_at = min(requested_expires, ceiling)

    queue_row = FederationOutboundQueue(
        envelope_id=envelope_id,
        envelope_data=envelope_dict,
        target_relay=recipient.home_relay,
        status=FedQueueStatus.PENDING,
        attempts=0,
        next_attempt_at=now,   # try immediately on next worker tick
        created_at=now,
    )
    db.add(queue_row)
    await db.flush()

    logger.info(
        "Queued federation envelope %s for %s (recipient %s)",
        envelope_id, recipient.home_relay, body.to[:16],
    )

    return EnvelopeAck(
        envelope_id=envelope_id, queued=True, expires_at=expires_at,
    )


@router.get(
    "",
    summary="List pending envelopes addressed to me",
)
async def list_my_inbox(
    current: CurrentSession,
    redis: RedisClient,
    limit: int = 50,
) -> dict:
    if limit < 1 or limit > 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="limit_must_be_1_to_200",
        )
    envelopes = await list_inbox(redis, current.pubkey_hex, limit=limit)
    return {"envelopes": envelopes, "count": len(envelopes)}


@router.get(
    "/{envelope_id}",
    summary="Fetch the encrypted blob bytes for an envelope",
    response_class=Response,
)
async def get_envelope_blob(
    envelope_id: str,
    current: CurrentSession,
    redis: RedisClient,
) -> Response:
    if len(envelope_id) != 64 or not all(c in "0123456789abcdef" for c in envelope_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_envelope_id",
        )

    inbox = await list_inbox(redis, current.pubkey_hex, limit=200)
    if not any(e["envelope_id"] == envelope_id for e in inbox):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="envelope_not_in_your_inbox",
        )

    blob = await blob_storage.read_blob(envelope_id)
    if blob is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="blob_not_found",
        )

    return Response(content=blob, media_type="application/octet-stream")


@router.delete(
    "/{envelope_id}",
    summary="Acknowledge an envelope has been received",
)
async def ack_envelope(
    envelope_id: str,
    current: CurrentSession,
    redis: RedisClient,
) -> dict:
    if len(envelope_id) != 64 or not all(c in "0123456789abcdef" for c in envelope_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_envelope_id",
        )
    await acknowledge_envelope(redis, current.pubkey_hex, envelope_id)
    return {"acknowledged": True}
