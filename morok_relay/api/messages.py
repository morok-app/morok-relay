"""
Message endpoints — REST send and polling fetch.

POST   /api/v1/messages           — submit an envelope (authenticated)
GET    /api/v1/messages           — list pending envelopes for caller
GET    /api/v1/messages/{id}      — fetch blob bytes for a specific envelope
DELETE /api/v1/messages/{id}      — acknowledge delivery (removes from inbox)

For real-time delivery, prefer the WebSocket endpoint /ws/v1/inbox — REST
fetch is for catch-up after coming back online.
"""
from __future__ import annotations

import base64
import logging

from fastapi import APIRouter, HTTPException, Response, status

from .. import blob_storage, crypto
from ..config import get_settings
from ..deps import CurrentSession, RedisClient
from ..queue import (
    acknowledge_envelope,
    enqueue_envelope,
    envelope_exists,
    list_inbox,
)
from ..schemas import EnvelopeAck, EnvelopeIn

logger = logging.getLogger(__name__)

router = APIRouter(tags=["messages"])


@router.post(
    "",
    response_model=EnvelopeAck,
    summary="Submit a message envelope",
)
async def submit_envelope(
    body: EnvelopeIn,
    current: CurrentSession,
    redis: RedisClient,
) -> EnvelopeAck:
    """
    Accept an envelope from the authenticated sender, verify its signature,
    queue it for delivery to the recipient.

    The 'from' field MUST match the authenticated session pubkey — we don't
    allow sending on behalf of someone else.
    """
    settings = get_settings()

    # 1. Authorization check: caller can only send AS themselves.
    if body.from_ != current.pubkey_hex:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="from_field_must_match_authenticated_pubkey",
        )

    # 2. Reconstruct the envelope as the client would have signed it and
    #    verify. Note: schemas.py uses alias 'from' for 'from_', so when
    #    we build the dict for crypto verification we must reverse that.
    envelope_dict = {
        "from": body.from_,
        "to": body.to,
        "ts": body.ts,
        "ttl": body.ttl,
        "blob": body.blob,
        "sig": body.sig,
    }
    ok, err = crypto.verify_envelope_signature(envelope_dict)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"envelope_invalid: {err}",
        )

    # 3. Decode blob and check size limit
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

    # 4. Compute envelope_id (deterministic for dedup)
    envelope = crypto.MessageEnvelope(
        sender_pubkey=bytes.fromhex(body.from_),
        recipient_pubkey=bytes.fromhex(body.to),
        timestamp=body.ts,
        ttl_seconds=body.ttl,
        blob=blob_bytes,
    )
    envelope_id = envelope.envelope_id

    # 5. Dedup: if we already have this exact envelope, just ack.
    if await envelope_exists(redis, envelope_id):
        return EnvelopeAck(
            envelope_id=envelope_id,
            queued=False,
            expires_at=0,  # caller should not retry; envelope already processed
        )

    # 6. Write blob to disk first, then enqueue. If enqueue fails, blob
    #    becomes orphan and gets cleaned by the reaper (separate concern).
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
        envelope_id=envelope_id,
        queued=True,
        expires_at=expires_at,
    )


@router.get(
    "",
    summary="List pending envelopes for the authenticated user",
)
async def list_pending(
    current: CurrentSession,
    redis: RedisClient,
    limit: int = 50,
) -> dict:
    """
    Returns metadata for up to `limit` pending envelopes addressed to
    the authenticated user.

    Does NOT include the blob bytes — fetch each via GET /messages/{id}.
    Does NOT mark as delivered — that's the job of DELETE /messages/{id}.
    """
    if limit < 1 or limit > 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="limit_must_be_1_to_200",
        )

    envelopes = await list_inbox(redis, current.pubkey_hex, limit=limit)
    return {"envelopes": envelopes, "count": len(envelopes)}


@router.get(
    "/{envelope_id}",
    summary="Fetch the encrypted blob for an envelope",
)
async def fetch_blob(
    envelope_id: str,
    current: CurrentSession,
    redis: RedisClient,
) -> Response:
    """
    Return the encrypted blob bytes. Caller MUST be the recipient — we don't
    let anyone other than the addressee fetch a blob, even if they know its ID.

    Returns 404 if envelope not found, 403 if caller is not the recipient.
    """
    if len(envelope_id) != 64 or not all(
        c in "0123456789abcdef" for c in envelope_id
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_envelope_id",
        )

    # Check envelope is in the recipient's inbox (also serves as auth check)
    envelopes = await list_inbox(redis, current.pubkey_hex, limit=200)
    if not any(e["envelope_id"] == envelope_id for e in envelopes):
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
    summary="Acknowledge delivery and remove from inbox",
)
async def ack_envelope(
    envelope_id: str,
    current: CurrentSession,
    redis: RedisClient,
) -> dict:
    """
    Mark this envelope as delivered. Removes it from the inbox; the reaper
    job will eventually secure-delete the blob.

    Idempotent: if envelope is already gone, returns acknowledged=False.
    """
    removed = await acknowledge_envelope(redis, current.pubkey_hex, envelope_id)
    return {"acknowledged": removed}
