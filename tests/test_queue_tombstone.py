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


# ── TTL на inbox-ключі (аудит 4, MEDIUM-3) ───────────────────────────────
async def test_inbox_key_has_ttl(redis):
    """
    Сам ZSET inbox'а мусить мати TTL. Без нього `maxmemory-policy
    volatile-ttl` не може витіснити жодного inbox'а під тиском пам'яті —
    policy стає декоративною, і Redis іде в OOM. (Знайдено на бойовому
    relay1: усі morok:inbox:* мали TTL = -1.)
    """
    eid = "e1" * 32
    await q.enqueue_envelope(redis, **_mk(eid))
    ttl = await redis.ttl(f"morok:inbox:{RCP}")
    assert ttl > 0, "inbox-ключ без TTL — volatile-ttl не спрацює"
    assert ttl >= 3600, "TTL коротший за життя конверта — втратимо конверти"


async def test_inbox_ttl_extends_with_new_envelopes(redis):
    """Живий inbox не помирає передчасно: TTL зсувається з кожним конвертом."""
    await q.enqueue_envelope(redis, **_mk("e2" * 32))
    await redis.expire(f"morok:inbox:{RCP}", 100)  # імітуємо майже протухлий
    await q.enqueue_envelope(redis, **_mk("e3" * 32))
    ttl = await redis.ttl(f"morok:inbox:{RCP}")
    assert ttl > 1000, "новий конверт не подовжив життя inbox-ключа"


async def test_group_fanout_sets_inbox_ttl(redis):
    """Груповий шлях теж має виставляти TTL (окремий код від DM)."""
    members = [f"{i:064x}" for i in range(1, 4)]
    await q.enqueue_envelope_for_recipients(
        redis,
        envelope_id="e4" * 32,
        sender_pubkey_hex=SND,
        recipient_pubkeys_hex=members,
        timestamp=int(time.time()),
        ttl_seconds=3600,
        signature_hex="ff" * 64,
        hard_ceiling_seconds=86400,
        group_id="11111111-2222-3333-4444-555555555555",
    )
    for pk in members:
        assert await redis.ttl(f"morok:inbox:{pk}") > 0


# ── temp-сироти (аудит 5) ────────────────────────────────────────────────
def test_reaper_removes_stale_temp_files(tmp_path):
    """
    write_blob пише в УНІКАЛЬНИЙ temp на кожен виклик. Якщо процес помер
    між створенням temp і os.replace (SIGKILL/OOM), сирота лишається — і
    кожен збій додає НОВИЙ файл. _iter_blob_paths їх свідомо пропускає,
    тож без reap_stale_temp_files їх не прибирає ніхто: диск тече.
    """
    import os

    from morok_relay.scripts.reaper import (
        STALE_TMP_AGE_SECONDS,
        reap_stale_temp_files,
    )

    now = int(time.time())
    eid = "ab" * 32

    fresh = tmp_path / f".{eid}.111.aaaa.tmp"
    fresh.write_bytes(b"x")
    stale = tmp_path / f".{eid}.222.bbbb.tmp"
    stale.write_bytes(b"x")
    old_mtime = now - STALE_TMP_AGE_SECONDS - 60
    os.utime(stale, (old_mtime, old_mtime))
    real = tmp_path / eid
    real.write_bytes(b"payload")

    stats = reap_stale_temp_files(tmp_path, now)

    assert stats["tmp_deleted"] == 1
    assert not stale.exists(), "покинутий temp не прибрано"
    assert fresh.exists(), "знесено temp запису, що може тривати"
    assert real.exists(), "знесено справжній блоб!"


def test_reaper_temp_cleanup_handles_missing_dir(tmp_path):
    from morok_relay.scripts.reaper import reap_stale_temp_files
    stats = reap_stale_temp_files(tmp_path / "nope", int(time.time()))
    assert stats == {"tmp_scanned": 0, "tmp_deleted": 0, "tmp_errors": 0}
