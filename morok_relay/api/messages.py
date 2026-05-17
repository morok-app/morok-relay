"""
Direct (1-on-1) message endpoints.

Rate-limited per pubkey on the POST endpoint to prevent message-spam attacks.
GET/DELETE are not limited — they only touch caller's own inbox.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Response, status

from .. import blob_storage, crypto
from ..config import get_settings
from ..deps import CurrentSession, RedisClient
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
    summary="Submit an encrypted envelope for delivery",
    dependencies=[Depends(rate_limit_by_pubkey(
        "messages_send",
        get_settings().rate_limit_messages_per_minute,
    ))],
)
async def send_envelope(
    body: EnvelopeIn,
    current: CurrentSession,
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

    h = hashlib.sha256()
    h.update(sender_pubkey)
    h.update(recipient_pubkey)
    h.update(body.ts.to_bytes(8, "big"))
    h.update(hashlib.sha256(blob_bytes).digest())
    envelope_id = h.hexdigest()

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
    return EnvelopeAck(envelope_id=envelope_id, queued=True, expires_at=expires_at)


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
