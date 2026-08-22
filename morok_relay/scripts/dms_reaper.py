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
import logging
import sys
import time

import redis.asyncio as redis_async
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..config import get_settings
from ..crypto import canonical_json, ed25519_sign
from ..db import close_db, init_db
from ..models import DeadManSwitch, DMSStatus
from ..queue import write_blob_then_enqueue

logger = logging.getLogger(__name__)


# ============================================================================
# Trigger logic
# ============================================================================

def build_dms_attestation_message(
    *,
    envelope_id: str,
    recipient_pubkey_hex: str,
    timestamp: int,
    dms_creator_pubkey_hex: str,
    dms_id: str,
) -> bytes:
    """
    Канонічне повідомлення ОКРЕМОЇ доменної атестації DMS-тригера.

    ЧОМУ ОКРЕМИЙ ПІДПИС, А НЕ РОЗШИРЕНИЙ КОНВЕРТ. Підпис самого конверта
    в Morok рахується РІВНО над crypto.SIGNED_FIELDS
    (from/to/ts/ttl/blob) — так підписує клієнт, так перевіряє
    verify_envelope_signature, і так мусить робити релей, інакше його
    підпис не перевірить ніхто. Але клієнту все одно треба
    криптографічно (а не «на слово metadata») знати, що конверт — це
    спрацьований заповіт саме такого-то автора. Тому дві незалежні
    підписані структури над одним конвертом:

      1. sig  — стандартний envelope signature (5 канонічних полів),
                перевіряється тим самим кодом, що й будь-який інший
                конверт;
      2. dms_attestation_sig — ця атестація, доменно розділена
                ("morok_dms_trigger": "v1"), прив'язана до конкретного
                envelope_id + одержувача + моменту, тож її не можна
                переграти на інший конверт.

    Обидва — ключем релею. Клієнт знає relay pubkey з DNS/handshake.
    """
    return canonical_json({
        "morok_dms_trigger": "v1",
        "envelope_id": envelope_id,
        "to": recipient_pubkey_hex,
        "ts": timestamp,
        "dms_creator_pubkey": dms_creator_pubkey_hex,
        "dms_id": dms_id,
    })


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

    ВИПРАВЛЕНО (детальний аналіз relay, P1 — зламана релізна фіча).
    Було ДВІ незалежні поломки в одній функції:

    1. ПІДПИС БУВ НЕПЕРЕВІРЮВАНИЙ. Релей підписував dict із ВОСЬМИ
       полів (5 канонічних + kind/dms_creator_pubkey/dms_id), а
       crypto.verify_envelope_signature рахує канонічний JSON рівно з
       П'ЯТИ (SIGNED_FIELDS). Доведено емпірично: перевірка падала і
       для урізаного, і для повного конверта — DMS-підпис релею не міг
       пройти НІКОЛИ, жодним клієнтом на стандартній схемі.
    2. МІТКИ НЕ ДОХОДИЛИ ДО КЛІЄНТА. kind/creator/dms_id писались у
       sidecar-ключ morok:dms:envelope:{id}, який НЕ читає жодне місце
       кодової бази (ні GET /messages/{id}, ні inbox). Одержувач бачив
       звичайний конверт від невідомого pubkey (релею) без жодної
       ознаки, що це спрацьований заповіт.

    Тепер: sig рахується над канонічною п'ятіркою (стандартна
    перевірка проходить), мітки їдуть у САМІЙ metadata конверта через
    enqueue_envelope(extra_meta=...) — як from_username/group_id, — а
    їх автентичність підтверджує окрема доменна атестація
    (build_dms_attestation_message). Sidecar-ключ прибрано.
    """
    settings = get_settings()
    now = int(time.time())

    # Use a fixed TTL for DMS deliveries — recipients have 24h to read.
    # If they're offline more than 24h, the message is lost. Owner can
    # re-arm by reactivating, but this is by design (per privacy promise).
    ttl_seconds = settings.message_ttl_hard_seconds

    # Compute envelope_id (stable for dedup if we retry)
    h = hashlib.sha256()
    h.update(dms.id.bytes)
    h.update(recipient_pubkey)
    h.update(dms.payload_encrypted)
    envelope_id = h.hexdigest()

    recipient_hex = recipient_pubkey.hex()
    creator_hex = dms.creator_pubkey.hex()
    dms_id_str = str(dms.id)

    # ── 1. Підпис конверта: РІВНО canonical SIGNED_FIELDS ──────────────
    payload_b64 = base64.b64encode(dms.payload_encrypted).decode()
    sig = ed25519_sign(canonical_json({
        "from": relay_pubkey_hex,
        "to": recipient_hex,
        "ts": now,
        "ttl": ttl_seconds,
        "blob": payload_b64,
    }), relay_priv)

    # ── 2. Доменна атестація DMS-тригера ──────────────────────────────
    attestation_sig = ed25519_sign(
        build_dms_attestation_message(
            envelope_id=envelope_id,
            recipient_pubkey_hex=recipient_hex,
            timestamp=now,
            dms_creator_pubkey_hex=creator_hex,
            dms_id=dms_id_str,
        ),
        relay_priv,
    )

    # Write blob and enqueue. write_blob_then_enqueue замість голої пари
    # write_blob()+enqueue_envelope(): при відмові постановки в чергу
    # (переповнений inbox одержувача, Redis недоступний) blob інакше
    # лишався сиротою на диску до наступного full-scan reaper'а. Той
    # самий helper уже використовують messages/mail/sealed/burner/
    # federation — dms_reaper був останнім місцем без нього.
    await write_blob_then_enqueue(
        envelope_id, dms.payload_encrypted,
        redis=redis,
        sender_pubkey_hex=relay_pubkey_hex,
        recipient_pubkey_hex=recipient_hex,
        timestamp=now,
        ttl_seconds=ttl_seconds,
        signature_hex=sig.hex(),
        hard_ceiling_seconds=settings.message_ttl_hard_seconds,
        extra_meta={
            "kind": "dms_trigger",
            "dms_creator_pubkey": creator_hex,
            "dms_id": dms_id_str,
            "dms_attestation_sig": attestation_sig.hex(),
        },
    )

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
