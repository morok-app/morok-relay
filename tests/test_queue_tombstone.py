"""
Черга конвертів: контракт enqueue (аудит 3) + tombstone sender-delete.

Перевіряємо:
  * None з enqueue_envelope означає РІВНО дедуп; збій Redis і повна черга
    кидають EnqueueRejected (чотири шляхи втрати повідомлень, закриті
    одним контрактом);
  * повний inbox одержувача → recipient_queue_full;
  * tombstone: авторизація sender-delete після протухання meta,
    spam-примітив «delete-подія для довільного envelope_id» закритий;
  * sealed-конверти tombstone не отримують (там preimage-ключ).
"""
from __future__ import annotations

import asyncio
import time

import pytest

from morok_relay import queue as q

pytestmark = pytest.mark.asyncio

SND, RCP, EVE = "11" * 32, "22" * 32, "33" * 32


def _mk(eid: str):
    return dict(
        envelope_id=eid,
        sender_pubkey_hex=SND,
        recipient_pubkey_hex=RCP,
        timestamp=int(time.time()),
        ttl_seconds=3600,
        signature_hex="ff" * 64,
        hard_ceiling_seconds=86400,
    )


# ── контракт enqueue ─────────────────────────────────────────────────────
async def test_none_means_exactly_dedup(redis):
    eid = "ab" * 32
    first = await q.enqueue_envelope(redis, **_mk(eid))
    assert first is not None
    second = await q.enqueue_envelope(redis, **_mk(eid))
    assert second is None  # і ТІЛЬКИ це значення означає «вже є»


async def test_expired_envelope_raises_not_none(redis):
    kw = _mk("ba" * 32)
    kw["timestamp"] = int(time.time()) - 7200  # ts+ttl у минулому
    with pytest.raises(q.EnqueueRejected):
        await q.enqueue_envelope(redis, **kw)


async def test_redis_failure_raises_not_none(redis, monkeypatch):
    """Збій Redis під час enqueue → EnqueueRejected, НЕ тихий None."""
    async def boom(*a, **kw):
        raise ConnectionError("redis down")

    monkeypatch.setattr(redis, "zremrangebyscore", boom)
    with pytest.raises(q.EnqueueRejected):
        await q.enqueue_envelope(redis, **_mk("bc" * 32))


async def test_full_inbox_rejects(redis, monkeypatch):
    """Черга одержувача переповнена → recipient_queue_full."""
    monkeypatch.setattr(q, "MAX_INBOX_QUEUE_DEPTH", 5)
    for i in range(5):
        await q.enqueue_envelope(redis, **_mk(f"{i:02x}" * 32))
    with pytest.raises(q.EnqueueRejected) as e:
        await q.enqueue_envelope(redis, **_mk("f9" * 32))
    assert e.value.detail == "recipient_queue_full"


# ── tombstone sender-delete ──────────────────────────────────────────────
async def test_tombstone_written_and_outlives_meta(redis):
    eid = "cd" * 32
    await q.enqueue_envelope(redis, **_mk(eid))
    assert await redis.get(f"morok:env_tomb:{eid}") is not None
    tomb_ttl = await redis.ttl(f"morok:env_tomb:{eid}")
    assert tomb_ttl > 3600 + 6 * 86400  # meta-TTL + ~7 днів


async def test_delete_with_live_meta(redis):
    eid = "ce" * 32
    await q.enqueue_envelope(redis, **_mk(eid))
    res = await q.delete_envelope_by_sender(redis, eid, EVE, RCP)
    assert res["error"] == "not_sender"
    res = await q.delete_envelope_by_sender(redis, eid, SND, RCP)
    assert res["ok"] and res["meta_existed"]
    assert await redis.get(f"morok:env_tomb:{eid}") is None  # прибраний


async def test_delete_after_meta_expiry_via_tombstone(redis):
    """Сценарій аудиту: meta протухла/ack-нута, tombstone авторизує."""
    eid = "cf" * 32
    await q.enqueue_envelope(redis, **_mk(eid))
    await redis.delete(f"morok:envelope:{eid}")  # імітуємо ack

    # чужак — відмова (раніше: ok=True + spam-подія в канал)
    assert (await q.delete_envelope_by_sender(redis, eid, EVE, RCP))["error"] == "not_sender"
    # правильний sender, але чужий recipient — хеш пари не збігся
    assert (await q.delete_envelope_by_sender(redis, eid, SND, EVE))["error"] == "not_sender"
    # справжня пара — ок
    res = await q.delete_envelope_by_sender(redis, eid, SND, RCP)
    assert res["ok"] and not res["meta_existed"]


async def test_spam_primitive_closed(redis):
    """Неіснуючий envelope_id → not_found і ЖОДНОЇ події в канал."""
    ch = redis.pubsub()
    await ch.subscribe(f"morok:inbox:channel:{RCP}")
    await asyncio.sleep(0.05)

    res = await q.delete_envelope_by_sender(redis, "d0" * 32, EVE, RCP)
    assert res["error"] == "not_found"
    msg = await ch.get_message(ignore_subscribe_messages=True, timeout=0.4)
    assert msg is None, f"spam-подія просочилась у канал: {msg}"
    await ch.aclose()


async def test_sealed_gets_no_tombstone(redis):
    eid = "d1" * 32
    await q.enqueue_envelope(
        redis,
        envelope_id=eid,
        sender_pubkey_hex="",
        recipient_pubkey_hex=RCP,
        timestamp=int(time.time()),
        ttl_seconds=3600,
        signature_hex="",
        hard_ceiling_seconds=86400,
        sealed=True,
        delete_key_hash="aa" * 32,
    )
    assert await redis.get(f"morok:env_tomb:{eid}") is None
