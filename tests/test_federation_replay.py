"""
Федерація: anti-replay підписаних подій (аудит 4, HIGH-1).

Знахідка: `_verify_delete_sig` приймав подію, якщо підпис вірний і ts у
вікні 7 днів, а дедупу не було. Отже, валідно підписану ДЕСТРУКТИВНУ
подію (group_gone, dm_delete, group_delete*) скомпрометований або
зловмисний trusted-peer міг переграти повторно протягом тижня — клієнти
локальних членів знову зносили групу / знову втрачали конверт.

Тут перевіряємо два шари фіксу:
  1. `_claim_federated_event` — подія витрачається рівно один раз;
  2. вікна ts розділені: дані (7 днів) vs control-plane (1 година).
"""
from __future__ import annotations

import time

import pytest

from morok_relay.api.federation import (
    CONTROL_SIG_WINDOW_SECONDS,
    DELETE_SIG_WINDOW_SECONDS,
    _claim_federated_event,
    _verify_delete_sig,
)

pytestmark = pytest.mark.asyncio

# Синхронні тести нижче помічені @pytest.mark.asyncio(False) — глобальний
# pytestmark інакше чіпляє їх як корутини.

SIGNER = "ab" * 32
GID = "11111111-2222-3333-4444-555555555555"


# ── дедуп ────────────────────────────────────────────────────────────────
async def test_first_claim_succeeds_replay_blocked(redis):
    ts = int(time.time())
    kw = dict(kind="group_gone", signer_pubkey_hex=SIGNER, ts=ts, group_id=GID)

    assert await _claim_federated_event(redis, **kw) is True
    # той самий підписаний payload — повтор
    assert await _claim_federated_event(redis, **kw) is False
    assert await _claim_federated_event(redis, **kw) is False


async def test_claim_key_has_ttl(redis):
    ts = int(time.time())
    await _claim_federated_event(
        redis, kind="group_gone", signer_pubkey_hex=SIGNER, ts=ts,
        group_id=GID, window_seconds=CONTROL_SIG_WINDOW_SECONDS,
    )
    keys = [k async for k in redis.scan_iter("morok:fed_seen:*")]
    assert len(keys) == 1
    ttl = await redis.ttl(keys[0])
    assert 0 < ttl <= CONTROL_SIG_WINDOW_SECONDS


async def test_distinct_events_do_not_collide(redis):
    """Дедуп не має схлопувати РІЗНІ легітимні події."""
    ts = int(time.time())
    base = dict(kind="dm_delete", signer_pubkey_hex=SIGNER, ts=ts)

    assert await _claim_federated_event(redis, **base, envelope_id="aa" * 32)
    # інший конверт — окрема подія
    assert await _claim_federated_event(redis, **base, envelope_id="bb" * 32)
    # інший підписант
    assert await _claim_federated_event(
        redis, kind="dm_delete", signer_pubkey_hex="cd" * 32, ts=ts,
        envelope_id="aa" * 32,
    )
    # інший ts (нове видалення тим самим ключем пізніше)
    assert await _claim_federated_event(
        redis, kind="dm_delete", signer_pubkey_hex=SIGNER, ts=ts + 1,
        envelope_id="aa" * 32,
    )
    # інший kind з тими самими полями
    assert await _claim_federated_event(
        redis, kind="group_delete", signer_pubkey_hex=SIGNER, ts=ts,
        envelope_id="aa" * 32,
    )


async def test_fails_open_when_redis_down(redis, monkeypatch):
    """
    Збій Redis не має зупиняти федерацію: втрата доступності гірша за
    ризик повтору, який і так вимагає скомпрометованого довіреного peer.
    """
    async def boom(*a, **kw):
        raise ConnectionError("redis down")

    monkeypatch.setattr(redis, "set", boom)
    assert await _claim_federated_event(
        redis, kind="group_gone", signer_pubkey_hex=SIGNER,
        ts=int(time.time()), group_id=GID,
    ) is True


# ── вікна ts ─────────────────────────────────────────────────────────────
async def test_control_window_is_much_narrower_than_data_window():
    assert CONTROL_SIG_WINDOW_SECONDS < DELETE_SIG_WINDOW_SECONDS
    assert CONTROL_SIG_WINDOW_SECONDS <= 3600
    assert DELETE_SIG_WINDOW_SECONDS == 7 * 86400


async def test_stale_ts_rejected_before_signature_check():
    """
    Подія, старша за вікно, відхиляється незалежно від підпису — це
    другий шар проти дуже старих повторів (перший — дедуп-ключ, який
    після TTL зникає; саме тому вікно і TTL мусять збігатися).
    """
    old_ts = int(time.time()) - (CONTROL_SIG_WINDOW_SECONDS + 60)
    assert _verify_delete_sig(
        kind="group_gone", envelope_id="", ts=old_ts,
        sig_hex="ff" * 64, signer_pubkey_hex=SIGNER, group_id=GID,
        ts_window_seconds=CONTROL_SIG_WINDOW_SECONDS,
    ) is False


async def test_malformed_input_never_raises():
    """Поля з недовіреного конверта не мають валити 500."""
    for bad in (None, "not-a-number", [], {}):
        assert _verify_delete_sig(
            kind="dm_delete", envelope_id="x", ts=bad,
            sig_hex="ff" * 64, signer_pubkey_hex=SIGNER,
        ) is False
    assert _verify_delete_sig(
        kind="dm_delete", envelope_id="x", ts=int(time.time()),
        sig_hex="zz", signer_pubkey_hex=SIGNER,
    ) is False
