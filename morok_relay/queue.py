"""
Per-recipient message queue in Redis.

For each recipient pubkey, we maintain a sorted set of envelope_ids that
are awaiting delivery. The score is the message's hard expiry timestamp
(creation_time + ttl, capped at hard ceiling) — this lets us efficiently
prune expired entries.

We also publish on a per-recipient channel for real-time delivery via
the WebSocket inbox endpoint. As of the delete-feature pass, channel
payloads are JSON events of the form:
    {"kind": "new", "envelope_id": "..."}
    {"kind": "deleted", "envelope_id": "...", "by": "<pubkey_hex>",
     "group_id": "<uuid>"|null}

The WS reader has a backward-compat path that treats a bare envelope_id
string as a "new" event, so a half-rolled deploy doesn't drop messages.

Keys
----
    morok:inbox:{recipient_pubkey_hex}     — SORTED SET of envelope_ids
                                             score = expires_at
    morok:envelope:{envelope_id}           — JSON of envelope metadata
                                             TTL = hard ceiling

    morok:inbox:channel:{recipient_pubkey} — Redis PUB/SUB channel
                                             message = JSON event
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time

import redis.asyncio as redis_async

logger = logging.getLogger(__name__)

# Hard cap on how many envelopes may sit in one recipient's inbox queue
# at once. Anti-flood storage guard — a recipient who hasn't been online
# can accumulate at most this many pending messages; beyond it, new sends
# are refused until they drain. Generous enough never to bite normal use
# (even a chatty group over days), tight enough to bound disk/Redis per
# user. Expired envelopes are pruned before this is checked, so it only
# counts live, undelivered messages.
MAX_INBOX_QUEUE_DEPTH = 5000


def _inbox_key(recipient_pubkey_hex: str) -> str:
    return f"morok:inbox:{recipient_pubkey_hex}"


def _envelope_meta_key(envelope_id: str) -> str:
    return f"morok:envelope:{envelope_id}"


def _inbox_channel(recipient_pubkey_hex: str) -> str:
    return f"morok:inbox:channel:{recipient_pubkey_hex}"


def _new_event(envelope_id: str) -> str:
    # JSON now (was bare envelope_id); reader_task in inbox.py recognises
    # both legacy bare-id and tagged-event formats.
    return json.dumps({"kind": "new", "envelope_id": envelope_id})


def _deleted_event(
    envelope_id: str,
    deleted_by_pubkey_hex: str,
    group_id: str | None = None,
) -> str:
    return json.dumps({
        "kind": "deleted",
        "envelope_id": envelope_id,
        "by": deleted_by_pubkey_hex,
        "group_id": group_id,
    })


def _read_event(
    envelope_id: str,
    reader_pubkey_hex: str,
    group_id: str | None = None,
) -> str:
    return json.dumps({
        "kind": "read",
        "envelope_id": envelope_id,
        "reader": reader_pubkey_hex,
        "group_id": group_id,
    })


def _group_gone_event(group_id: str, by_pubkey_hex: str) -> str:
    return json.dumps({
        "kind": "group_gone",
        "group_id": group_id,
        "by": by_pubkey_hex,
    })


async def publish_group_gone(
    redis: redis_async.Redis,
    recipient_pubkeys_hex: list[str],
    group_id: str,
    by_pubkey_hex: str,
) -> None:
    """
    Notify group members that the group was deleted by its creator.

    Ephemeral push (like read receipts): if a member's WS is offline,
    the event is lost — but that's fine, because clients also detect
    deleted groups lazily (GET /groups/{id} -> 404 on next open).
    """
    event = _group_gone_event(group_id, by_pubkey_hex)
    for pk in recipient_pubkeys_hex:
        try:
            await redis.publish(_inbox_channel(pk), event)
        except Exception as e:
            logger.warning(
                "publish_group_gone failed for %s: %s", pk[:8], e,
            )


async def publish_read_receipt(
    redis: redis_async.Redis,
    sender_pubkey_hex: str,
    envelope_id: str,
    reader_pubkey_hex: str,
    group_id: str | None = None,
) -> None:
    """
    Notify a sender that one of their messages was read.

    No persistent storage — this is an ephemeral push. If the sender's
    WS is offline at this moment, the event is lost; the client will
    not retroactively learn that an old message was read after coming
    back online. That's by design: read receipts are best-effort, the
    relay should not keep state about who read what.
    """
    try:
        await redis.publish(
            _inbox_channel(sender_pubkey_hex),
            _read_event(envelope_id, reader_pubkey_hex, group_id),
        )
    except Exception as e:
        logger.warning(
            "publish_read_receipt failed for sender %s: %s",
            sender_pubkey_hex[:8], e,
        )


async def enqueue_envelope(
    redis: redis_async.Redis,
    envelope_id: str,
    sender_pubkey_hex: str,
    recipient_pubkey_hex: str,
    timestamp: int,
    ttl_seconds: int,
    signature_hex: str,
    hard_ceiling_seconds: int,
    sender_username: str | None = None,
    sealed: bool = False,
    delete_key_hash: str | None = None,
) -> int | None:
    """
    Add an envelope to the recipient's inbox queue and publish a notification.

    Sealed Sender: when `sealed=True`, `sender_pubkey_hex`/`signature_hex`
    are empty strings — sender identity lives INSIDE the encrypted blob
    and is verified by the recipient client. `delete_key_hash` (sha256
    hex) lets the anonymous sender later prove deletion rights by
    presenting the preimage — without revealing who they are.

    `sender_username` is the username of the sender AT SEND TIME — included
    in the metadata so the recipient's client can display "@bob" instead of
    a raw pubkey prefix without doing a separate lookup.

    Returns the expires_at timestamp (capped at hard ceiling), or None
    if the envelope already exists in Redis (dedup hit). The atomic
    SET NX is the dedup gate — using a separate envelope_exists() check
    here would leave a TOCTOU window where two concurrent sends with the
    same envelope_id could both pass the check and double-deliver.
    """
    now = int(time.time())
    requested_expires = timestamp + ttl_seconds
    ceiling = now + hard_ceiling_seconds
    expires_at = min(requested_expires, ceiling)
    ttl_until_expiry = expires_at - now
    if ttl_until_expiry <= 0:
        # Already expired before it was even queued — nothing to do.
        return None

    # ── Per-recipient queue cap (anti-flood storage guard) ──
    # Hard physical limit on how many envelopes may wait for one recipient
    # at once. Independent of the Redis rate-limiter (which is a separate,
    # fail-open layer) — this protects storage even if that limiter is
    # bypassed or Redis-side counters are unavailable. We first drop
    # expired rows so a backlog of stale envelopes can't wedge delivery
    # for a recipient who simply hasn't been online.
    try:
        await redis.zremrangebyscore(_inbox_key(recipient_pubkey_hex), 0, now)
        depth = await redis.zcard(_inbox_key(recipient_pubkey_hex))
        if depth >= MAX_INBOX_QUEUE_DEPTH:
            # Recipient's queue is full. Reject — sender (or their relay)
            # will see this as a delivery failure and can retry later once
            # the recipient drains their inbox.
            return None
    except Exception as e:
        # Redis hiccup on the cap check — do NOT fail-open into unbounded
        # growth. Treat as "cannot guarantee headroom" and refuse.
        logger.warning("inbox queue-depth check failed, refusing enqueue: %s", e)
        return None

    meta = {
        "envelope_id": envelope_id,
        "from": sender_pubkey_hex,
        "from_username": sender_username,
        "to": recipient_pubkey_hex,
        "ts": timestamp,
        "ttl": ttl_seconds,
        "sig": signature_hex,
        "expires_at": expires_at,
    }
    if sealed:
        meta["sealed"] = True
        if delete_key_hash:
            meta["delete_key_hash"] = delete_key_hash

    # SET NX is the dedup gate — only one writer "wins" the slot.
    written = await redis.set(
        _envelope_meta_key(envelope_id),
        json.dumps(meta).encode("utf-8"),
        ex=ttl_until_expiry,
        nx=True,
    )
    if not written:
        # Already exists (a previous send / retry won the race). The
        # inbox row and notification were already published by that
        # caller — do nothing.
        return None

    async with redis.pipeline(transaction=True) as pipe:
        pipe.zadd(_inbox_key(recipient_pubkey_hex), {envelope_id: expires_at})
        pipe.publish(_inbox_channel(recipient_pubkey_hex), _new_event(envelope_id))
        await pipe.execute()

    return expires_at


async def enqueue_envelope_for_recipients(
    redis: redis_async.Redis,
    envelope_id: str,
    sender_pubkey_hex: str,
    recipient_pubkeys_hex: list[str],
    timestamp: int,
    ttl_seconds: int,
    signature_hex: str,
    hard_ceiling_seconds: int,
    group_id: str | None = None,
    sender_username: str | None = None,
) -> tuple[int, int]:
    """
    Fan-out: deliver the same envelope to multiple recipients.

    Used by group messages — one blob is queued in N inboxes. The same
    envelope_id is reused for all of them (each inbox row points to the
    same blob on disk).

    Returns (expires_at, recipient_count).

    The metadata is stored ONCE with a 'to' of either the group_id (if
    given) or "broadcast" otherwise. This means /messages GET returns the
    same metadata to every recipient — they all see the message addressed
    to the group, not to themselves individually. That's what we want for
    group UX.
    """
    now = int(time.time())
    requested_expires = timestamp + ttl_seconds
    ceiling = now + hard_ceiling_seconds
    expires_at = min(requested_expires, ceiling)

    to_value = group_id if group_id else "broadcast"

    meta = {
        "envelope_id": envelope_id,
        "from": sender_pubkey_hex,
        "from_username": sender_username,
        "to": to_value,
        "ts": timestamp,
        "ttl": ttl_seconds,
        "sig": signature_hex,
        "expires_at": expires_at,
        "group_id": group_id,
    }

    new_event = _new_event(envelope_id)

    # Per-recipient queue cap: prune expired then skip any recipient whose
    # inbox is already at the depth limit. Unlike the DM path we DON'T
    # refuse the whole send — other group members must still get the
    # message; only the flooded inbox is skipped.
    eligible: list[str] = []
    for recipient in recipient_pubkeys_hex:
        try:
            await redis.zremrangebyscore(_inbox_key(recipient), 0, now)
            if await redis.zcard(_inbox_key(recipient)) < MAX_INBOX_QUEUE_DEPTH:
                eligible.append(recipient)
            else:
                logger.warning(
                    "inbox full for %s — skipping in group fan-out",
                    recipient[:8],
                )
        except Exception as e:
            # On a check error, skip this recipient rather than risk
            # unbounded growth. They'll catch up via a later message.
            logger.warning("queue-depth check failed for %s: %s", recipient[:8], e)

    async with redis.pipeline(transaction=True) as pipe:
        pipe.set(
            _envelope_meta_key(envelope_id),
            json.dumps(meta).encode("utf-8"),
            ex=expires_at - now,
        )
        for recipient in eligible:
            pipe.zadd(_inbox_key(recipient), {envelope_id: expires_at})
            pipe.publish(_inbox_channel(recipient), new_event)
        await pipe.execute()

    return expires_at, len(eligible)


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

    await redis.zremrangebyscore(_inbox_key(recipient_pubkey_hex), 0, now)

    envelope_ids_raw = await redis.zrange(
        _inbox_key(recipient_pubkey_hex), 0, limit - 1
    )
    envelope_ids = [eid.decode("utf-8") for eid in envelope_ids_raw]

    if not envelope_ids:
        return []

    async with redis.pipeline(transaction=False) as pipe:
        for eid in envelope_ids:
            pipe.get(_envelope_meta_key(eid))
        metas_raw = await pipe.execute()

    out = []
    for raw in metas_raw:
        if raw is None:
            continue
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return out


async def get_envelope_meta(
    redis: redis_async.Redis,
    envelope_id: str,
) -> dict | None:
    """
    Fetch envelope metadata directly by id.

    Returns None if the envelope has expired or been deleted. Used by
    the WS reader to look up metadata for a single notification without
    re-scanning the whole inbox.
    """
    raw = await redis.get(_envelope_meta_key(envelope_id))
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


async def acknowledge_envelope(
    redis: redis_async.Redis,
    recipient_pubkey_hex: str,
    envelope_id: str,
) -> bool:
    """
    Mark envelope as delivered for THIS recipient: remove from inbox.

    For group messages, this only removes from the current recipient's
    inbox — other group members still see the message until they ack
    individually. The blob is not deleted until the reaper sees that NO
    recipient still has it queued (or it ages out).
    """
    removed = await redis.zrem(_inbox_key(recipient_pubkey_hex), envelope_id)
    return removed > 0


async def envelope_exists(redis: redis_async.Redis, envelope_id: str) -> bool:
    """Check if an envelope is known to this relay (for dedup)."""
    return bool(await redis.exists(_envelope_meta_key(envelope_id)))


async def delete_envelope_by_sender(
    redis: redis_async.Redis,
    envelope_id: str,
    caller_pubkey_hex: str,
    recipient_pubkey_hex: str,
) -> dict:
    """
    Sender removes their DM envelope from the recipient's inbox.

    If metadata is still in Redis we authorize via meta.from. If it has
    already expired or been acked by the recipient, we accept the
    caller's claim and publish a delete event into the recipient's
    channel anyway — the recipient client is expected to sanity-check
    that the envelope_id really belongs to a chat with `caller`.

    The blob file is left for the reaper to clean up once no inbox row
    references it.

    Returns
    -------
    dict with keys:
        ok: bool                  — operation accepted
        deleted_from_queue: bool  — envelope row was actually present
        meta_existed: bool        — recipient had not yet acked
        error: str | None         — "not_sender" | "group_message"
                                  | "recipient_mismatch" | None
    """
    meta_raw = await redis.get(_envelope_meta_key(envelope_id))
    meta_existed = meta_raw is not None

    if meta_existed:
        try:
            meta = json.loads(meta_raw)
        except json.JSONDecodeError:
            meta = {}

        if meta.get("group_id"):
            return {
                "ok": False, "deleted_from_queue": False,
                "meta_existed": True, "error": "group_message",
            }
        if meta.get("from") != caller_pubkey_hex:
            return {
                "ok": False, "deleted_from_queue": False,
                "meta_existed": True, "error": "not_sender",
            }
        if meta.get("to") != recipient_pubkey_hex:
            return {
                "ok": False, "deleted_from_queue": False,
                "meta_existed": True, "error": "recipient_mismatch",
            }

    event_payload = _deleted_event(envelope_id, caller_pubkey_hex)

    async with redis.pipeline(transaction=True) as pipe:
        pipe.zrem(_inbox_key(recipient_pubkey_hex), envelope_id)
        pipe.delete(_envelope_meta_key(envelope_id))
        pipe.publish(_inbox_channel(recipient_pubkey_hex), event_payload)
        results = await pipe.execute()

    return {
        "ok": True,
        "deleted_from_queue": bool(results[0]),
        "meta_existed": meta_existed,
        "error": None,
    }


async def delete_sealed_envelope(
    redis: redis_async.Redis,
    envelope_id: str,
    delete_key_hex: str,
) -> dict:
    """
    Anonymous sender deletes their SEALED envelope by presenting the
    preimage of the delete_key_hash stored in the envelope meta.

    Unlike delete_envelope_by_sender we CANNOT fall back to trusting the
    caller when meta has expired — there is no authenticated identity to
    trust. No meta => nothing to authorize against => error.

    Returns dict: ok, deleted_from_queue, error
        error: "not_found" | "not_sealed" | "wrong_key" | None
    """
    meta_raw = await redis.get(_envelope_meta_key(envelope_id))
    if meta_raw is None:
        return {"ok": False, "deleted_from_queue": False, "error": "not_found"}
    try:
        meta = json.loads(meta_raw)
    except json.JSONDecodeError:
        return {"ok": False, "deleted_from_queue": False, "error": "not_found"}

    if not meta.get("sealed") or not meta.get("delete_key_hash"):
        return {"ok": False, "deleted_from_queue": False, "error": "not_sealed"}

    try:
        presented = hashlib.sha256(bytes.fromhex(delete_key_hex)).hexdigest()
    except ValueError:
        return {"ok": False, "deleted_from_queue": False, "error": "wrong_key"}
    if not hmac.compare_digest(presented, meta["delete_key_hash"]):
        return {"ok": False, "deleted_from_queue": False, "error": "wrong_key"}

    recipient_pubkey_hex = meta.get("to") or ""
    # deleted_by порожній — відправник анонімний навіть у delete-події.
    event_payload = _deleted_event(envelope_id, "")

    async with redis.pipeline(transaction=True) as pipe:
        pipe.zrem(_inbox_key(recipient_pubkey_hex), envelope_id)
        pipe.delete(_envelope_meta_key(envelope_id))
        pipe.publish(_inbox_channel(recipient_pubkey_hex), event_payload)
        results = await pipe.execute()

    return {
        "ok": True,
        "deleted_from_queue": bool(results[0]),
        "error": None,
    }


async def delete_envelope_for_group(
    redis: redis_async.Redis,
    envelope_id: str,
    group_id: str,
    recipient_pubkeys_hex: list[str],
    deleted_by_pubkey_hex: str,
) -> dict:
    """
    Remove a group envelope from every member's inbox and push a delete
    event onto each member's channel.

    Authorization (sender-or-admin) is enforced in the router because
    it requires a DB lookup against the group membership table.

    Returns
    -------
    dict with keys:
        deleted_from_count: int   — how many member inboxes still had it
        meta_existed: bool        — metadata was still in Redis
        broadcast_to: int         — channels we published the event on
    """
    meta_key = _envelope_meta_key(envelope_id)
    meta_existed = bool(await redis.exists(meta_key))

    event_payload = _deleted_event(
        envelope_id, deleted_by_pubkey_hex, group_id=group_id,
    )

    async with redis.pipeline(transaction=True) as pipe:
        pipe.delete(meta_key)
        for r in recipient_pubkeys_hex:
            pipe.zrem(_inbox_key(r), envelope_id)
            pipe.publish(_inbox_channel(r), event_payload)
        results = await pipe.execute()

    # Layout: [delete_meta, zrem_0, publish_0, zrem_1, publish_1, ...]
    # zrem results live at indices 1, 3, 5, ...
    deleted_from_count = sum(
        1 for i in range(1, len(results), 2) if results[i]
    )

    return {
        "deleted_from_count": deleted_from_count,
        "meta_existed": meta_existed,
        "broadcast_to": len(recipient_pubkeys_hex),
    }
