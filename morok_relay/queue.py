"""
Per-recipient message queue in Redis.

For each recipient pubkey, we maintain a sorted set of envelope_ids that
are awaiting delivery. The score is the message's hard expiry timestamp
(creation_time + ttl, capped at hard ceiling) — this lets us efficiently
prune expired entries.

We also publish on a per-recipient channel for real-time delivery via
the WebSocket inbox endpoint.

Keys
----
    morok:inbox:{recipient_pubkey_hex}     — SORTED SET of envelope_ids
                                             score = expires_at
    morok:envelope:{envelope_id}           — HASH of envelope metadata
                                             (sender, recipient, ts, ttl, sig)
                                             TTL = hard ceiling

    morok:inbox:channel:{recipient_pubkey} — Redis PUB/SUB channel
                                             message = envelope_id
"""
from __future__ import annotations

import json
import logging
import time

import redis.asyncio as redis_async

logger = logging.getLogger(__name__)


def _inbox_key(recipient_pubkey_hex: str) -> str:
    return f"morok:inbox:{recipient_pubkey_hex}"


def _envelope_meta_key(envelope_id: str) -> str:
    return f"morok:envelope:{envelope_id}"


def _inbox_channel(recipient_pubkey_hex: str) -> str:
    return f"morok:inbox:channel:{recipient_pubkey_hex}"


async def enqueue_envelope(
    redis: redis_async.Redis,
    envelope_id: str,
    sender_pubkey_hex: str,
    recipient_pubkey_hex: str,
    timestamp: int,
    ttl_seconds: int,
    signature_hex: str,
    hard_ceiling_seconds: int,
) -> int:
    """
    Add an envelope to the recipient's inbox queue and publish a notification.

    Returns the expires_at timestamp (capped at hard ceiling).
    """
    now = int(time.time())
    requested_expires = timestamp + ttl_seconds
    ceiling = now + hard_ceiling_seconds
    expires_at = min(requested_expires, ceiling)

    meta = {
        "envelope_id": envelope_id,
        "from": sender_pubkey_hex,
        "to": recipient_pubkey_hex,
        "ts": timestamp,
        "ttl": ttl_seconds,
        "sig": signature_hex,
        "expires_at": expires_at,
    }

    async with redis.pipeline(transaction=True) as pipe:
        # Store metadata as JSON; TTL on the key itself for auto-cleanup
        pipe.set(
            _envelope_meta_key(envelope_id),
            json.dumps(meta).encode("utf-8"),
            ex=expires_at - now,
        )
        # Add to recipient's sorted-set inbox with expiry as score
        pipe.zadd(_inbox_key(recipient_pubkey_hex), {envelope_id: expires_at})
        # Notify any active inbox WebSocket subscribers
        pipe.publish(_inbox_channel(recipient_pubkey_hex), envelope_id)
        await pipe.execute()

    return expires_at


async def list_inbox(
    redis: redis_async.Redis,
    recipient_pubkey_hex: str,
    limit: int = 50,
) -> list[dict]:
    """
    Get pending envelope metadata for a recipient.

    Returns oldest-first. Caller usually wants to fetch blob via
    blob_storage for each envelope, then mark delivered.
    """
    now = int(time.time())

    # First, prune any expired entries (score <= now)
    await redis.zremrangebyscore(_inbox_key(recipient_pubkey_hex), 0, now)

    envelope_ids_raw = await redis.zrange(
        _inbox_key(recipient_pubkey_hex), 0, limit - 1
    )
    envelope_ids = [eid.decode("utf-8") for eid in envelope_ids_raw]

    if not envelope_ids:
        return []

    # Batch-fetch metadata
    async with redis.pipeline(transaction=False) as pipe:
        for eid in envelope_ids:
            pipe.get(_envelope_meta_key(eid))
        metas_raw = await pipe.execute()

    out = []
    for raw in metas_raw:
        if raw is None:
            continue  # metadata expired but inbox entry survived; will be cleaned
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return out


async def acknowledge_envelope(
    redis: redis_async.Redis,
    recipient_pubkey_hex: str,
    envelope_id: str,
) -> bool:
    """
    Mark envelope as delivered: remove from recipient's inbox.

    Note: this does NOT delete the blob from disk. The relay's reaper job
    (separate worker) is responsible for that — but ack is the signal that
    delivery succeeded, so blob can be reaped sooner.

    Returns True if the envelope was in the inbox and got removed.
    """
    removed = await redis.zrem(_inbox_key(recipient_pubkey_hex), envelope_id)
    return removed > 0


async def envelope_exists(redis: redis_async.Redis, envelope_id: str) -> bool:
    """Check if an envelope is known to this relay (for dedup)."""
    return bool(await redis.exists(_envelope_meta_key(envelope_id)))
