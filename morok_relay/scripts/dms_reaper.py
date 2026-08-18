"""
Dead Man's Switch reaper — find armed DMS that should fire, fire them.

Run manually:
    python -m morok_relay.scripts.dms_reaper

Or via systemd timer (preferred — see deploy/morok-dms-reaper.{service,timer}).

What it does
------------
1. Find all 'armed' DMS where (now - last_check_in_at) > trigger_seconds.
2. For each, deliver the encrypted payload to every recipient as a regular
   1-on-1 envelope addressed FROM creator_pubkey TO recipient_pubkey.
3. Mark the DMS as 'triggered' and record triggered_at + delivered_at per
   recipient.

Idempotent: a DMS in 'triggered' state is never picked up again. If the
process crashes mid-delivery, some recipients may already have delivered_at
set — on restart, only the un-delivered ones get redelivered. The DMS itself
is not flipped to 'triggered' until ALL recipients are delivered (or skipped).

Signing
-------
The payload-bearing envelope is delivered as if from creator_pubkey. The
relay does NOT have the creator's private key, so it cannot sign as them.
Instead, the relay signs with its OWN signing key, and clients should
display "DMS-triggered message from @<creator_username>" rather than
treating it as a normal signed message.

Clients can verify authenticity by checking that:
- The relay's signature is valid (relay pubkey is known via DNS/handshake)
- The envelope contains a creator pubkey field
- The envelope is tagged as DMS-trigger (we add a "kind": "dms_trigger" marker)
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import sys
import time

import redis.asyncio as redis_async
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..blob_storage import write_blob
from ..config import get_settings
from ..crypto import canonical_json, ed25519_sign
from ..db import close_db, init_db
from ..models import DeadManSwitch, DMSStatus
from ..queue import enqueue_envelope

logger = logging.getLogger(__name__)


# ============================================================================
# Trigger logic
# ============================================================================

async def _build_and_deliver_envelope(
    redis: redis_async.Redis,
    dms: DeadManSwitch,
    recipient_pubkey: bytes,
    relay_priv: bytes,
    relay_pubkey_hex: str,
) -> str:
    """
    Build a DMS-triggered envelope and deliver it to one recipient.

    Returns envelope_id. Does NOT mark recipient as delivered — caller does.
    """
    settings = get_settings()
    now = int(time.time())

    # Use a fixed TTL for DMS deliveries — recipients have 24h to read.
    # If they're offline more than 24h, the message is lost. Owner can
    # re-arm by reactivating, but this is by design (per privacy promise).
    ttl_seconds = settings.message_ttl_hard_seconds

    # Envelope body
    payload_b64 = base64.b64encode(dms.payload_encrypted).decode()
    unsigned = {
        "from": relay_pubkey_hex,                # signed by relay
        "to": recipient_pubkey.hex(),
        "ts": now,
        "ttl": ttl_seconds,
        "blob": payload_b64,
        "kind": "dms_trigger",                   # client distinguishes from regular envelope
        "dms_creator_pubkey": dms.creator_pubkey.hex(),
        "dms_id": str(dms.id),
    }
    sig = ed25519_sign(canonical_json(unsigned), relay_priv)
    envelope = {**unsigned, "sig": sig.hex()}

    # Compute envelope_id (stable for dedup if we retry)
    h = hashlib.sha256()
    h.update(dms.id.bytes)
    h.update(recipient_pubkey)
    h.update(dms.payload_encrypted)
    envelope_id = h.hexdigest()

    # Write blob and enqueue
    await write_blob(envelope_id, dms.payload_encrypted)
    await enqueue_envelope(
        redis=redis,
        envelope_id=envelope_id,
        sender_pubkey_hex=relay_pubkey_hex,
        recipient_pubkey_hex=recipient_pubkey.hex(),
        timestamp=now,
        ttl_seconds=ttl_seconds,
        signature_hex=sig.hex(),
        hard_ceiling_seconds=settings.message_ttl_hard_seconds,
    )

    # Stash the full envelope metadata so clients fetching via
    # GET /messages/{id} get the kind/creator hint.
    meta_key = f"morok:dms:envelope:{envelope_id}"
    await redis.setex(meta_key, ttl_seconds, json.dumps({
        "kind": "dms_trigger",
        "dms_creator_pubkey": dms.creator_pubkey.hex(),
        "dms_id": str(dms.id),
    }).encode("utf-8"))

    return envelope_id


async def fire_dms_switches() -> dict:
    """
    Find armed DMS that should fire, deliver to each recipient, mark triggered.
    """
    settings = get_settings()
    now = int(time.time())

    stats = {
        "dms_scanned": 0,
        "dms_fired": 0,
        "dms_skipped_not_due": 0,
        "envelopes_delivered": 0,
        "errors": 0,
    }

    # Validate relay signing key is configured
    try:
        relay_priv = bytes.fromhex(settings.relay_privkey_hex)
    except (ValueError, TypeError):
        logger.error("MOROK_RELAY_PRIVKEY_HEX not configured — cannot fire DMS")
        stats["errors"] += 1
        return stats
    if len(relay_priv) != 32:
        logger.error("MOROK_RELAY_PRIVKEY_HEX wrong length")
        stats["errors"] += 1
        return stats

    from ..db import _session_factory
    if _session_factory is None:
        logger.error("DB session factory not initialized")
        stats["errors"] += 1
        return stats

    redis = redis_async.from_url(settings.redis_url, decode_responses=False)
    try:
        await redis.ping()
    except Exception as e:
        logger.error("Cannot connect to Redis: %s", e)
        await redis.aclose()
        stats["errors"] += 1
        return stats

    try:
        async with _session_factory() as db:
            # Беремо ЛИШЕ ті, що вже прострочені, і одразу під блокуванням.
            #
            # Раніше вибирались усі ARMED, вік рахувався в Python, і між
            # цим читанням та розсилкою користувач міг зробити check-in:
            # його транзакція комітилась, а reaper продовжував працювати
            # зі старим об'єктом і все одно розсилав payload. Людина
            # підтвердила, що жива — а секрет уже пішов.
            #
            # Тепер:
            #   * умова "прострочено" рахується в SQL на свіжих даних;
            #   * FOR UPDATE тримає рядок до кінця нашої транзакції, тож
            #     check-in/cancel чекають і далі бачать уже не-ARMED;
            #   * SKIP LOCKED пропускає ті DMS, які саме зараз редагує
            #     користувач — такий просто дочекається наступного
            #     запуску (щогодини), уже зі свіжим last_check_in_at.
            #
            # of=DeadManSwitch — блокуємо лише сам DMS, не рядки
            # recipients, підтягнуті selectinload.
            stmt = (
                select(DeadManSwitch)
                .where(DeadManSwitch.status == DMSStatus.ARMED)
                .where(
                    DeadManSwitch.last_check_in_at
                    + DeadManSwitch.trigger_seconds <= now
                )
                .options(selectinload(DeadManSwitch.recipients))
                .with_for_update(of=DeadManSwitch, skip_locked=True)
            )
            armed = (await db.execute(stmt)).scalars().all()

            for dms in armed:
                stats["dms_scanned"] += 1
                age = now - dms.last_check_in_at
                if age < dms.trigger_seconds:
                    stats["dms_skipped_not_due"] += 1
                    continue

                logger.info(
                    "Firing DMS %s (creator=%s, age=%ds, recipients=%d)",
                    str(dms.id)[:8],
                    dms.creator_pubkey.hex()[:16],
                    age,
                    len(dms.recipients),
                )

                # Deliver to each recipient. Process even if some fail —
                # don't lose the chance to deliver to others.
                all_delivered = True
                for r in dms.recipients:
                    if r.delivered_at is not None:
                        continue  # already delivered on prior run
                    try:
                        await _build_and_deliver_envelope(
                            redis=redis,
                            dms=dms,
                            recipient_pubkey=r.recipient_pubkey,
                            relay_priv=relay_priv,
                            relay_pubkey_hex=settings.relay_pubkey_hex,
                        )
                        r.delivered_at = now
                        stats["envelopes_delivered"] += 1
                    except Exception as e:
                        logger.exception(
                            "Failed to deliver DMS %s to %s: %s",
                            str(dms.id)[:8],
                            r.recipient_pubkey.hex()[:16],
                            e,
                        )
                        stats["errors"] += 1
                        all_delivered = False

                # Only flip to triggered if every recipient is delivered
                if all_delivered:
                    dms.status = DMSStatus.TRIGGERED
                    dms.triggered_at = now
                    # Scrub (аудит зовн. №3, HIGH): payload вже доставлений
                    # усім одержувачам як звичайний конверт (з власним TTL
                    # у черзі) — тримати ще один повний ciphertext-копію в
                    # DeadManSwitch назавжди сенсу не має.
                    dms.payload_encrypted = b""
                    stats["dms_fired"] += 1
                # else: stays armed; next run retries un-delivered recipients
                #       (payload MUST stay intact until all_delivered — do
                #       not scrub early, un-delivered recipients still need it)

            await db.commit()
    finally:
        await redis.aclose()

    return stats


# ============================================================================
# Entry
# ============================================================================

def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )


async def _main() -> int:
    _setup_logging()
    logger.info("morok-dms-reaper starting")
    start = time.monotonic()

    await init_db()
    try:
        stats = await fire_dms_switches()
    finally:
        await close_db()

    elapsed = time.monotonic() - start
    logger.info(
        "morok-dms-reaper done: scanned=%d fired=%d skipped=%d "
        "delivered=%d errors=%d elapsed=%.2fs",
        stats.get("dms_scanned", 0),
        stats.get("dms_fired", 0),
        stats.get("dms_skipped_not_due", 0),
        stats.get("envelopes_delivered", 0),
        stats.get("errors", 0),
        elapsed,
    )
    return 0 if stats.get("errors", 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
