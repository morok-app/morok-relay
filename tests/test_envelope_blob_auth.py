"""
get_envelope_blob: хибний 404 при черзі понад 200 конвертів (жорсткий
свіжий прохід — не з зовнішнього аудиту, знайдено при повторному
читанні коду).

Знахідка: авторизація перевірялась через list_inbox(limit=200) — "чи
id входить у перші 200 найстаріших записів". При черзі понад 200
(максимум за дизайном 5000, MAX_INBOX_QUEUE_DEPTH) власник конверта
№201+ отримував хибний 404 попри те, що конверт реально в його черзі.
Фікс — is_envelope_in_inbox через ZSCORE, O(1), коректний для будь-
якого розміру черги.
"""
from __future__ import annotations

import time

import pytest

from morok_relay import queue as q

pytestmark = pytest.mark.asyncio

RECIPIENT = "aa" * 32
SENDER = "bb" * 32


def _mk(eid: str) -> dict:
    return dict(
        envelope_id=eid,
        sender_pubkey_hex=SENDER,
        recipient_pubkey_hex=RECIPIENT,
        timestamp=int(time.time()),
        ttl_seconds=3600,
        signature_hex="ff" * 64,
        hard_ceiling_seconds=86400,
    )


# ── is_envelope_in_inbox: чиста логіка ────────────────────────────────────
async def test_present_envelope_returns_true(redis):
    eid = "cc" * 32
    await q.enqueue_envelope(redis, **_mk(eid))
    assert await q.is_envelope_in_inbox(redis, RECIPIENT, eid) is True


async def test_absent_envelope_returns_false(redis):
    assert await q.is_envelope_in_inbox(
        redis, RECIPIENT, "dd" * 32,
    ) is False


async def test_other_users_envelope_not_visible(redis):
    eid = "ee" * 32
    await q.enqueue_envelope(redis, **_mk(eid))
    other_recipient = "ff" * 32
    assert await q.is_envelope_in_inbox(redis, other_recipient, eid) is False


# ── ГОЛОВНИЙ ТЕСТ: понад 200 у черзі, старий підхід провалився б ─────────
async def test_envelope_beyond_first_200_still_found(redis, monkeypatch):
    """
    Наскрізне відтворення реального сценарію. Ставимо 250 конвертів у
    чергу, перевіряємо, що і 5-й (у "перших 200"), і 249-й (ЗА межею
    старого limit=200 підходу) обидва коректно розпізнаються як
    належні власнику.
    """
    monkeypatch.setattr(q, "MAX_INBOX_QUEUE_DEPTH", 300)  # щоб 250 пройшло

    all_ids = []
    for i in range(250):
        eid = f"{i:04x}" * 16  # 64 hex chars
        await q.enqueue_envelope(redis, **_mk(eid))
        all_ids.append(eid)

    early_id = all_ids[5]     # у перших 200 — стара логіка теж знайшла б
    late_id = all_ids[249]    # ЗА межею 200 — стара логіка НЕ знайшла б

    assert await q.is_envelope_in_inbox(redis, RECIPIENT, early_id) is True
    assert await q.is_envelope_in_inbox(redis, RECIPIENT, late_id) is True, \
        "конверт за межею перших 200 хибно не розпізнаний як належний"


# ── наскрізно через ендпоінт ──────────────────────────────────────────────
async def test_get_envelope_blob_succeeds_beyond_200_in_queue(
    redis, monkeypatch,
):
    """
    Наскрізний тест на сам ендпоінт. Без фіксу цей запит впав би з 404
    "envelope_not_in_your_inbox" для конверта, що реально належить
    користувачу, лише тому що чергу переповнено понад 200 записів.
    """
    from morok_relay import blob_storage
    from morok_relay.api.messages import get_envelope_blob
    from morok_relay.sessions import Session

    monkeypatch.setattr(q, "MAX_INBOX_QUEUE_DEPTH", 300)

    late_id = None
    for i in range(220):
        eid = f"{i:04x}" * 16
        await q.enqueue_envelope(redis, **_mk(eid))
        if i == 210:
            late_id = eid

    async def fake_read_blob(_eid):
        return b"encrypted-content"
    monkeypatch.setattr(blob_storage, "read_blob", fake_read_blob)

    session = Session(token="t" * 64, pubkey_hex=RECIPIENT, expires_at=2**31)
    response = await get_envelope_blob(late_id, session, redis)
    assert response.status_code == 200
    assert response.body == b"encrypted-content"


async def test_get_envelope_blob_still_404_for_foreign_envelope(redis):
    """Контроль: чужий конверт (не в черзі викликача) досі коректно
    відхиляється — фікс не відкрив доступ до чужого."""
    from fastapi import HTTPException

    from morok_relay.api.messages import get_envelope_blob
    from morok_relay.sessions import Session

    other_recipient = "12" * 32
    eid = "34" * 32
    await q.enqueue_envelope(redis, **{**_mk(eid), "recipient_pubkey_hex": other_recipient})

    session = Session(token="t" * 64, pubkey_hex=RECIPIENT, expires_at=2**31)
    with pytest.raises(HTTPException) as e:
        await get_envelope_blob(eid, session, redis)
    assert e.value.status_code == 404
