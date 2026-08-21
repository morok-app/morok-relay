"""
Reaper full-scan масштабування (MEDIUM, фрешевий аудит: "reaper
масштабується як повний filesystem scan").

Знахідка: reaper робив rglob() над УСІМ blob_dir на КОЖНОМУ проході —
вартість завжди пропорційна ЗАГАЛЬНІЙ кількості файлів на диску,
незалежно від того, скільки з них реально прострочено. Для мільйонів
об'єктів це directory traversal + N stat() + N Redis EXISTS щоразу.

Фікс: Redis ZSET-індекс (envelope_id → expires_at), заповнюється в
queue.py на кожному enqueue (той самий pipeline, де вже пишеться meta
й pending SET — жоден із 9 call sites write_blob не чіпається).
reap_blobs_indexed() читає ЛИШЕ прострочені candidates одним
ZRANGEBYSCORE — вартість O(K), не O(усі файли). Filesystem-scan
лишається як reap_blobs_full_scan() — рідкісний (раз на добу) safety-
net для orphan-файлів, яких індекс не бачив.
"""
from __future__ import annotations

import time

import pytest

from morok_relay import blob_storage
from morok_relay import queue as q
from morok_relay.scripts import reaper

pytestmark = pytest.mark.asyncio

SENDER = "11" * 32
RECIPIENT = "22" * 32


def _mk(eid: str, recipient: str = RECIPIENT) -> dict:
    return dict(
        envelope_id=eid,
        sender_pubkey_hex=SENDER,
        recipient_pubkey_hex=recipient,
        timestamp=int(time.time()),
        ttl_seconds=3600,
        signature_hex="ff" * 64,
        hard_ceiling_seconds=86400,
    )


# ── enqueue заповнює індекс автоматично ───────────────────────────────────
async def test_dm_enqueue_populates_index(redis):
    eid = "aa" * 32
    await q.enqueue_envelope(redis, **_mk(eid))
    score = await redis.zscore(q._BLOB_EXPIRY_INDEX_KEY, eid)
    assert score is not None


async def test_group_enqueue_populates_index(redis):
    eid = "bb" * 32
    await q.enqueue_envelope_for_recipients(
        redis=redis, envelope_id=eid, sender_pubkey_hex=SENDER,
        recipient_pubkeys_hex=["11" * 32, "22" * 32],
        timestamp=int(time.time()), ttl_seconds=3600,
        signature_hex="ff" * 64, hard_ceiling_seconds=86400,
        group_id="g1",
    )
    score = await redis.zscore(q._BLOB_EXPIRY_INDEX_KEY, eid)
    assert score is not None


async def test_group_enqueue_populates_index_even_when_no_eligible(redis):
    """
    Навіть якщо ЖОДЕН одержувач не eligible (усі мали переповнену
    чергу) — blob фізично записаний, і його ID досі мусить потрапити
    в індекс, інакше він назавжди лишиться "невидимим" для indexed-
    reaper (файл на диску без жодного шляху дізнатись про нього, окрім
    рідкісного full-scan).
    """
    eid = "cc" * 32

    async def fake_pipeline_zero_eligible(*a, **kw):
        return 0

    import morok_relay.queue as qmod
    # Симулюємо "усі переповнені" безпосередньо через порожній список
    # eligible: підміняємо MAX_INBOX_QUEUE_DEPTH на 0, щоб жоден
    # одержувач не пройшов depth-check.
    orig = qmod.MAX_INBOX_QUEUE_DEPTH
    qmod.MAX_INBOX_QUEUE_DEPTH = 0
    try:
        await q.enqueue_envelope_for_recipients(
            redis=redis, envelope_id=eid, sender_pubkey_hex=SENDER,
            recipient_pubkeys_hex=["11" * 32],
            timestamp=int(time.time()), ttl_seconds=3600,
            signature_hex="ff" * 64, hard_ceiling_seconds=86400,
            group_id="g2",
        )
    finally:
        qmod.MAX_INBOX_QUEUE_DEPTH = orig

    score = await redis.zscore(q._BLOB_EXPIRY_INDEX_KEY, eid)
    assert score is not None, \
        "blob без жодного eligible одержувача випав з індексу назавжди"


# ── reap_blobs_indexed: основний прохід ───────────────────────────────────
async def test_indexed_reap_skips_not_yet_expired(redis, tmp_path, monkeypatch):
    monkeypatch.setattr(reaper, "get_settings", lambda: _settings_with(tmp_path))
    monkeypatch.setattr(blob_storage, "get_settings", lambda: _settings_with(tmp_path))

    eid = "dd" * 32
    await blob_storage.write_blob(eid, b"not-expired-yet")
    future = int(time.time()) + 3600
    await redis.zadd(q._BLOB_EXPIRY_INDEX_KEY, {eid: future})

    stats = await reaper.reap_blobs_indexed(redis)
    assert stats["indexed_candidates"] == 0
    assert await blob_storage.blob_exists(eid) is True


async def test_indexed_reap_deletes_expired_with_no_meta(redis, tmp_path, monkeypatch):
    """
    ГОЛОВНИЙ ТЕСТ. Candidate прострочений (score <= now) і meta вже
    немає (типова ситуація ПІСЛЯ ACK, чи природне протухання) —
    indexed-прохід має видалити файл, не сканувавши диск.
    """
    monkeypatch.setattr(reaper, "get_settings", lambda: _settings_with(tmp_path))
    monkeypatch.setattr(blob_storage, "get_settings", lambda: _settings_with(tmp_path))

    eid = "ee" * 32
    await blob_storage.write_blob(eid, b"expired-orphan")
    past = int(time.time()) - 10
    await redis.zadd(q._BLOB_EXPIRY_INDEX_KEY, {eid: past})
    # СВІДОМО не пишемо meta — імітує "вже ACK-нутий і видалений" стан.

    stats = await reaper.reap_blobs_indexed(redis)
    assert stats["indexed_deleted"] == 1
    assert await blob_storage.blob_exists(eid) is False
    assert await redis.zscore(q._BLOB_EXPIRY_INDEX_KEY, eid) is None, \
        "candidate мав бути прибраний з індексу після обробки"


async def test_indexed_reap_does_not_touch_still_queued(redis, tmp_path, monkeypatch):
    """Score вже минув, АЛЕ meta досі існує (edge-case округлення) —
    файл не чіпаємо, лише прибираємо candidate з індексу."""
    monkeypatch.setattr(reaper, "get_settings", lambda: _settings_with(tmp_path))
    monkeypatch.setattr(blob_storage, "get_settings", lambda: _settings_with(tmp_path))

    eid = "ff" * 32
    await blob_storage.write_blob(eid, b"still-queued")
    past = int(time.time()) - 10
    await redis.zadd(q._BLOB_EXPIRY_INDEX_KEY, {eid: past})
    await redis.set(f"morok:envelope:{eid}", b"{}", ex=100)

    stats = await reaper.reap_blobs_indexed(redis)
    assert stats["indexed_still_queued"] == 1
    assert await blob_storage.blob_exists(eid) is True


async def test_indexed_reap_never_scans_filesystem(redis, tmp_path, monkeypatch):
    """
    ГОЛОВНИЙ ТЕСТ на саму суть фіксу. indexed-прохід НЕ повинен
    звертатись до _iter_blob_paths (filesystem traversal) взагалі —
    навіть якщо в blob_dir лежать файли, яких немає в індексі.
    """
    monkeypatch.setattr(reaper, "get_settings", lambda: _settings_with(tmp_path))

    called = {"n": 0}
    real_iter = reaper._iter_blob_paths

    def counting_iter(*a, **kw):
        called["n"] += 1
        return real_iter(*a, **kw)

    monkeypatch.setattr(reaper, "_iter_blob_paths", counting_iter)

    # Порожній Redis-індекс, порожня файлова система — indexed-прохід
    # має завершитись, ЖОДНОГО разу не викликавши filesystem traversal.
    await reaper.reap_blobs_indexed(redis)
    assert called["n"] == 0, \
        "indexed-прохід звертався до диска — втратив сенс O(K) фіксу"


# ── reap_blobs_full_scan: safety net для незаіндексованих ────────────────
async def test_full_scan_catches_unindexed_orphan(redis, tmp_path, monkeypatch):
    """
    ГОЛОВНИЙ ТЕСТ на safety net. Файл записаний write_blob НАПРЯМУ, БЕЗ
    проходження через enqueue (тобто НІКОЛИ не потрапляв у Redis-
    індекс) — indexed-прохід його не бачить, full-scan бачить.
    """
    settings = _settings_with(tmp_path)
    monkeypatch.setattr(reaper, "get_settings", lambda: settings)
    monkeypatch.setattr(blob_storage, "get_settings", lambda: settings)

    eid = "12" * 32
    await blob_storage.write_blob(eid, b"never-indexed-orphan")
    # СВІДОМО не робимо жодного enqueue — файл існує на диску, індекс
    # про нього нічого не знає, meta теж немає.

    indexed_stats = await reaper.reap_blobs_indexed(redis)
    assert indexed_stats["indexed_candidates"] == 0
    assert await blob_storage.blob_exists(eid) is True, \
        "indexed-прохід не мав чіпати незаіндексований файл"

    full_stats = await reaper.reap_blobs_full_scan(redis)
    assert full_stats["blobs_deleted_delivered"] == 1
    assert await blob_storage.blob_exists(eid) is False, \
        "full-scan мав знайти й прибрати orphan, якого індекс не бачив"


def _settings_with(tmp_path):
    from morok_relay.config import get_settings
    settings = get_settings()
    settings.blob_dir = tmp_path
    return settings
