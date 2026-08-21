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
    delete_envelope_by_sender,
    enqueue_envelope,
    envelope_exists,
    is_envelope_in_inbox,
    list_inbox,
    publish_read_receipt,
    was_delivered_to,
    write_blob_then_enqueue,
)
from ..rate_limit import rate_limit_by_pubkey
from ..schemas import EnvelopeAck, EnvelopeIn
from ..push_sender import schedule_push

from pydantic import BaseModel, Field

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

    # Look up sender — for username snapshot
    sender_stmt = (
        select(User)
        .where(User.pubkey == sender_pubkey)
        .where(User.deleted_at.is_(None))
    )
    sender_user = (await db.execute(sender_stmt)).scalar_one_or_none()
    sender_username = sender_user.username if sender_user else None

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

        expires_at = await write_blob_then_enqueue(
            envelope_id, blob_bytes,
            redis=redis,
            sender_pubkey_hex=body.from_,
            recipient_pubkey_hex=body.to,
            timestamp=body.ts,
            ttl_seconds=body.ttl,
            signature_hex=body.sig,
            hard_ceiling_seconds=settings.message_ttl_hard_seconds,
            sender_username=sender_username,
        )
        if expires_at is None:
            # None тепер означає РІВНО дедуп: конверт із таким id уже в
            # черзі (наш ретрай або паралельне надсилання). Реальні
            # відмови — повна черга, протух, Redis лежить — приходять
            # винятком EnqueueRejected і віддають клієнту 429/400/503
            # замість цього псевдо-успіху.
            return EnvelopeAck(envelope_id=envelope_id, queued=False, expires_at=0)
        # Push notification — TRULY never blocks the response (аудит
        # зовн. №3): раніше цей блок мав власний try/except, але
        # `await trigger_push(...)` усе одно чекав на мережеву
        # round-trip до push-провайдера ДО повернення відповіді
        # клієнту. schedule_push() ставить задачу у фон і повертається
        # негайно.
        schedule_push(
            redis=redis,
            recipient_pubkeys_hex=[body.to],
            sender_username=sender_username,
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
        # Hint to the receiving relay so it can pre-populate username
        # in the inbox metadata.
        "from_username": sender_username,
    }

    requested_expires = body.ts + body.ttl
    ceiling = now + settings.message_ttl_hard_seconds
    expires_at = min(requested_expires, ceiling)

    queue_row = FederationOutboundQueue(
        envelope_id=envelope_id,
        envelope_data=envelope_dict,
        target_relay=recipient.home_relay,
        status=FedQueueStatus.PENDING,
        attempts=0,
        next_attempt_at=now,
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

    # ВИПРАВЛЕНО (жорсткий свіжий прохід): раніше перевіряли належність
    # через list_inbox(limit=200) — "чи id входить у перші 200
    # найстаріших записів". При черзі понад 200 (максимум за дизайном
    # 5000) власник конверта №201+ отримував хибний 404, попри те що
    # конверт реально в його черзі. is_envelope_in_inbox — пряма
    # ZSCORE-перевірка, коректна для будь-якого розміру черги.
    if not await is_envelope_in_inbox(redis, current.pubkey_hex, envelope_id):
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


class DMDeleteRequest(BaseModel):
    recipient_pubkey_hex: str = Field(
        ..., min_length=64, max_length=64,
        pattern=r"^[0-9a-fA-F]{64}$",
    )
    # Sender's Ed25519 signature over canonical_json({
    #   "kind": "dm_delete",
    #   "envelope_id": "<envelope_id>",
    #   "ts": <ts>,
    # }) — verified against current.pubkey_hex. Forwarded to the
    # recipient's home relay so they can also verify without trusting
    # the federation hop.
    signature_hex: str = Field(
        ..., min_length=128, max_length=128,
        pattern=r"^[0-9a-fA-F]{128}$",
    )
    ts: int = Field(..., ge=0)


class ReadReceiptItem(BaseModel):
    envelope_id: str = Field(
        ..., min_length=64, max_length=64, pattern=r"^[0-9a-fA-F]{64}$",
    )
    sender_pubkey_hex: str = Field(
        ..., min_length=64, max_length=64, pattern=r"^[0-9a-fA-F]{64}$",
    )
    group_id: str | None = Field(default=None, max_length=64)

    # Опціональний підпис reader'а (аудит зовн. №4, MEDIUM). Обидва поля
    # ОБОВ'ЯЗКОВО разом або відсутні разом — часткова пара безглузда.
    # Legacy-клієнти, що не вміють підписувати, лишають обидва None —
    # стара unsigned поведінка (задокументований у _handle_read_receipt
    # ризик: недобросовісний peer relay міг би вигадати receipt) не
    # зникає, поки клієнти цього не підтримають; тут лише готова
    # інфраструктура для сильнішого шляху, коли клієнт дозріє.
    reader_signature_hex: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{128}$",
    )
    signed_at: int | None = Field(default=None, ge=0)


class ReadReceiptsRequest(BaseModel):
    reads: list[ReadReceiptItem] = Field(..., min_length=1, max_length=100)


# Domain separation для підпису read receipt — той самий підхід, що
# auth verify ("morok_auth") і DMS check-in ("morok_dms_checkin").
_READ_RECEIPT_SIG_DOMAIN = "morok_read_receipt:v1"
_READ_RECEIPT_SIG_WINDOW_SECONDS = 300


def _verify_read_receipt_signature(
    *, envelope_id: str, sender_pubkey_hex: str, reader_pubkey_hex: str,
    group_id: str | None, signed_at: int, signature_hex: str,
) -> bool:
    """
    Ed25519-перевірка підпису READER'а над конкретним read receipt
    (аудит зовн. №4, MEDIUM). reader_pubkey_hex тут — ЗАВЖДИ
    current.pubkey_hex з верифікованої сесії, ніколи з тіла запиту:
    підмінити "хто підписав" через тіло неможливо.
    """
    now = int(time.time())
    if abs(now - signed_at) > _READ_RECEIPT_SIG_WINDOW_SECONDS:
        return False
    message = crypto.canonical_json({
        "morok_read_receipt": _READ_RECEIPT_SIG_DOMAIN,
        "envelope_id": envelope_id,
        "sender_pubkey_hex": sender_pubkey_hex,
        "reader_pubkey_hex": reader_pubkey_hex,
        "group_id": group_id,
        "signed_at": signed_at,
    })
    try:
        sig_bytes = bytes.fromhex(signature_hex)
        pubkey_bytes = bytes.fromhex(reader_pubkey_hex)
    except ValueError:
        return False
    return crypto.ed25519_verify(message, sig_bytes, pubkey_bytes)


@router.post(
    "/read",
    summary="Acknowledge that messages were read; notifies senders",
    dependencies=[Depends(rate_limit_by_pubkey(
        "messages_read",
        get_settings().rate_limit_messages_per_minute,
    ))],
)
async def post_read_receipts(
    body: ReadReceiptsRequest,
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
) -> dict:
    """
    Client tells us "I read these messages". We propagate the receipt
    to each message's sender (local WS push or cross-relay federation).

    No persistent storage: receipts are ephemeral, like envelopes. If
    the sender is offline at this moment, the receipt is silently lost.

    Privacy notes:
    - Receipts contain ONLY: which envelope, by which reader (this user).
    - Local receipts are implicitly authenticated by the bearer session
      (reader_pubkey_hex = current.pubkey_hex) — no extra signature
      needed for the LOCAL sender push.
    - Cross-relay: an unsigned receipt asks the sender's home relay to
      trust OUR relay's word for "user X read this". A misbehaving peer
      could fabricate one; impact is limited to a misleading checkmark,
      not plaintext exposure. Clients MAY now attach reader_signature_hex
      + signed_at (Ed25519 over the receipt) — when present, we verify
      it and forward the signature so the receiving relay can check it
      independently instead of trusting us. Legacy clients that don't
      sign keep working exactly as before.
    """
    settings = get_settings()
    reader_pubkey_hex = current.pubkey_hex
    sent = 0
    federated = 0
    skipped = 0

    for r in body.reads:
        # Reader never reads their own messages back to themselves
        if r.sender_pubkey_hex == reader_pubkey_hex:
            skipped += 1
            continue

        # Якщо клієнт НАМАГАВСЯ підписати (поле присутнє), але підпис
        # не проходить — краще явно відмовити цей конкретний елемент,
        # ніж тихо занизити гарантію до unsigned. Мовчазний даунгрейд
        # ховав би від клієнта, що щось зламалось.
        if r.reader_signature_hex is not None and r.signed_at is not None:
            if not _verify_read_receipt_signature(
                envelope_id=r.envelope_id,
                sender_pubkey_hex=r.sender_pubkey_hex,
                reader_pubkey_hex=reader_pubkey_hex,
                group_id=r.group_id,
                signed_at=r.signed_at,
                signature_hex=r.reader_signature_hex,
            ):
                skipped += 1
                continue

        try:
            sender_pubkey = bytes.fromhex(r.sender_pubkey_hex)
        except ValueError:
            skipped += 1
            continue

        # Entitlement-перевірка (жорсткий свіжий прохід, MEDIUM):
        # раніше сервер знав ХТО шле receipt (bearer) і чий підпис на
        # ньому, але не перевіряв, чи цей envelope_id взагалі був
        # адресований саме цьому reader'у. Bearer міг надіслати
        # "прочитано" для ЧУЖОГО envelope_id — не витік plaintext, але
        # фальшива галочка sender'у. was_delivered_to читає tombstone,
        # записаний у acknowledge_envelope на кожному реальному ACK —
        # переживає видалення meta (яке тепер відбувається одразу
        # після ACK, не чекає TTL).
        if not await was_delivered_to(redis, r.envelope_id, reader_pubkey_hex):
            skipped += 1
            continue

        stmt = (
            select(User)
            .where(User.pubkey == sender_pubkey)
            .where(User.deleted_at.is_(None))
        )
        sender_user = (await db.execute(stmt)).scalar_one_or_none()

        if sender_user is None:
            skipped += 1
            continue

        if sender_user.home_relay == settings.relay_name:
            # Local sender — push WS event directly
            await publish_read_receipt(
                redis=redis,
                sender_pubkey_hex=r.sender_pubkey_hex,
                envelope_id=r.envelope_id,
                reader_pubkey_hex=reader_pubkey_hex,
                group_id=r.group_id,
            )
            sent += 1
        elif sender_user.home_relay:
            # Cross-relay — queue a federation forward
            from .groups import _synthetic_queue_id  # avoid circular import
            target_relay = sender_user.home_relay
            payload = {
                "kind": "read_receipt",
                "envelope_id": r.envelope_id,
                "sender_pubkey_hex": r.sender_pubkey_hex,
                "reader_pubkey_hex": reader_pubkey_hex,
                "group_id": r.group_id,
            }
            # Якщо підпис пройшов верифікацію вище — передаємо його
            # далі. Приймаючий relay зможе перевірити НЕЗАЛЕЖНО, а не
            # довіряти нашому слову "user X read this".
            if r.reader_signature_hex is not None and r.signed_at is not None:
                payload["reader_signature_hex"] = r.reader_signature_hex
                payload["signed_at"] = r.signed_at
            synthetic_id = _synthetic_queue_id(
                "read", r.envelope_id, reader_pubkey_hex, target_relay,
            )
            dup_stmt = (
                select(FederationOutboundQueue)
                .where(FederationOutboundQueue.envelope_id == synthetic_id)
                .where(FederationOutboundQueue.target_relay == target_relay)
                .limit(1)
            )
            existing = (await db.execute(dup_stmt)).scalar_one_or_none()
            if existing is None:
                now = int(time.time())
                db.add(FederationOutboundQueue(
                    envelope_id=synthetic_id,
                    envelope_data=payload,
                    target_relay=target_relay,
                    status=FedQueueStatus.PENDING,
                    attempts=0,
                    next_attempt_at=now,
                    created_at=now,
                ))
                await db.flush()
            federated += 1
        else:
            skipped += 1

    return {"sent": sent, "federated": federated, "skipped": skipped}


@router.post(
    "/{envelope_id}/delete-for-recipient",
    summary="Sender deletes their DM message from the recipient's inbox",
)
async def delete_dm_message(
    envelope_id: str,
    body: DMDeleteRequest,
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
) -> dict:
    """
    Sender-initiated server-side delete of a DM.

    If the envelope is still in the recipient's queue, it's removed and a
    "deleted" event is pushed onto their WS channel. If the recipient has
    already acked it off the queue, the queue removal is a no-op but the
    WS event still goes out (so an online recipient client can also drop
    the message from its local store).

    Recipient-side sanity: the client must verify that `envelope_id` was
    indeed part of its chat with `by` (the sender) before deleting locally.
    """
    if len(envelope_id) != 64 or not all(
        c in "0123456789abcdef" for c in envelope_id
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_envelope_id",
        )

    # ── Verify sender signature on the delete request ──────────────────
    # Without this, a malicious trusted peer could fabricate "alice
    # deleted msg X" via federation — censorship by impersonation. We
    # require the sender to sign the delete intent so the recipient's
    # relay (next hop, may be us if same-relay) can verify cryptographically
    # before honouring it.
    now = int(time.time())
    if abs(now - body.ts) > 7 * 86400:
        # ±7 days window — generous for clock skew + offline-then-delete,
        # tight enough that a leaked signature can't be replayed forever.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="delete_ts_out_of_window",
        )
    sig_message = crypto.canonical_json({
        "kind":        "dm_delete",
        "envelope_id": envelope_id,
        "ts":          body.ts,
    })
    try:
        sig_bytes = bytes.fromhex(body.signature_hex)
        sender_pubkey = bytes.fromhex(current.pubkey_hex)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_signature_or_pubkey",
        )
    if not crypto.ed25519_verify(sig_message, sig_bytes, sender_pubkey):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_delete_signature",
        )

    result = await delete_envelope_by_sender(
        redis=redis,
        envelope_id=envelope_id,
        caller_pubkey_hex=current.pubkey_hex,
        recipient_pubkey_hex=body.recipient_pubkey_hex,
    )

    err = result.get("error")
    if err == "not_sender":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="not_message_sender",
        )
    if err == "group_message":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="use_group_delete_endpoint",
        )
    if err == "recipient_mismatch":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="recipient_mismatch",
        )
    # err == "not_found" (ні meta, ні tombstone) НЕ відхиляємо одразу:
    # для федеративного одержувача конверт локально ніколи не enqueue-
    # вався — це нормальний випадок, авторизацію робить домашній релей
    # одержувача (перевіряє підпис deleter'а і СВІЙ tombstone). Рішення —
    # нижче, після визначення federated_to.

    # Cross-relay propagation: if the recipient lives on a peer relay,
    # forward the delete event so that peer's Redis (and any online
    # client there) also drops the message. Local delete already
    # happened above (no-op if envelope was federated and never queued
    # locally).
    settings = get_settings()
    try:
        recipient_pubkey = bytes.fromhex(body.recipient_pubkey_hex)
    except ValueError:
        recipient_pubkey = None

    federated_to: str | None = None
    if recipient_pubkey is not None:
        stmt = (
            select(User)
            .where(User.pubkey == recipient_pubkey)
            .where(User.deleted_at.is_(None))
        )
        recipient_user = (await db.execute(stmt)).scalar_one_or_none()
        if (recipient_user is not None
                and recipient_user.home_relay
                and recipient_user.home_relay != settings.relay_name):
            target_relay = recipient_user.home_relay
            delete_payload = {
                "kind": "dm_delete",
                "envelope_id": envelope_id,
                "recipient_pubkey_hex": body.recipient_pubkey_hex,
                "deleted_by_pubkey_hex": current.pubkey_hex,
                # Forward the sender's signature so the recipient's relay
                # can verify the delete intent — federation trust alone
                # is not enough.
                "deleter_signature_hex": body.signature_hex,
                "deleter_ts": body.ts,
            }
            from .groups import _synthetic_queue_id
            synthetic_id = _synthetic_queue_id("dmdel", envelope_id, target_relay)
            dup_stmt = (
                select(FederationOutboundQueue)
                .where(FederationOutboundQueue.envelope_id == synthetic_id)
                .where(FederationOutboundQueue.target_relay == target_relay)
                .limit(1)
            )
            existing = (await db.execute(dup_stmt)).scalar_one_or_none()
            if existing is None:
                now = int(time.time())
                db.add(FederationOutboundQueue(
                    envelope_id=synthetic_id,
                    envelope_data=delete_payload,
                    target_relay=target_relay,
                    status=FedQueueStatus.PENDING,
                    attempts=0,
                    next_attempt_at=now,
                    created_at=now,
                ))
                await db.flush()
            federated_to = target_relay

    if err == "not_found" and federated_to is None:
        # Одержувач локальний (або невідомий), а ні metadata, ні
        # tombstone немає — конверт не існував чи видалення прийшло
        # надто пізно. Відмова БЕЗ delete-події в канал: раніше цей
        # шлях був spam-примітивом для довільних envelope_id.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="envelope_not_found",
        )
    logger.info(
        "DM %s... deleted by sender %s... (queue_hit=%s, meta_existed=%s, fed=%s)",
        envelope_id[:8], current.pubkey_hex[:8],
        result["deleted_from_queue"], result["meta_existed"], federated_to,
    )

    return {
        "deleted": True,
        "envelope_id": envelope_id,
        "deleted_from_queue": result["deleted_from_queue"],
        "recipient_already_acked": not result["meta_existed"],
        "federated_to_relay": federated_to,
    }
