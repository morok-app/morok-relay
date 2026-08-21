"""
ACK не видаляв ciphertext негайно (жорсткий свіжий прохід — не з
зовнішнього аудиту, знайдено при повторному читанні коду).

Знахідка: acknowledge_envelope() видаляв лише inbox-запис. Metadata
(morok:envelope:{id}) жила своїм повним TTL (годинами) незалежно від
ACK — README прямо обіцяє "після отримання видаляються і запис у
черзі, і файл із шифротекстом", код цього не робив: reaper бачив
"meta ще існує" і не чіпав файл аж до природного TTL.

Фікс: pending-recipient SET на кожен конверт (DM — один одержувач,
група — всі eligible), атомарний decrement+conditional-delete
(_ACK_PENDING_LUA) — видалення відбувається рівно на ОСТАННЬОМУ ACK,
не раніше і не пізніше. Legacy-конверти без pending-tracking (до
деплою фіксу) безпечно падають на стару поведінку (reaper).
"""
from __future__ import annotations

import asyncio
import time

import pytest

from morok_relay import blob_storage
from morok_relay import queue as q

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


async def _wait_for_task_completion():
    """acknowledge_envelope запускає видалення fire-and-forget
    (asyncio.create_task) — даємо event loop один тік, щоб задача
    встигла виконатись, перш ніж перевіряти результат."""
    await asyncio.sleep(0.05)


# ── DM: негайне видалення на єдиному ACK ─────────────────────────────────
async def test_dm_blob_deleted_immediately_after_ack(redis):
    """
    ГОЛОВНИЙ ТЕСТ. DM має рівно одного одержувача — ACK одразу
    спорожнює pending SET, meta й blob мають зникнути НЕГАЙНО, а не
    чекати на природний TTL (раніше — 3600с у цьому сценарії).
    """
    eid = "aa" * 32
    await blob_storage.write_blob(eid, b"secret-ciphertext")
    await q.enqueue_envelope(redis, **_mk(eid))

    assert await blob_storage.blob_exists(eid) is True
    assert await q.envelope_exists(redis, eid) is True

    await q.acknowledge_envelope(redis, RECIPIENT, eid)
    await _wait_for_task_completion()

    assert await q.envelope_exists(redis, eid) is False, \
        "meta не видалена одразу після ACK єдиного одержувача"
    assert await blob_storage.blob_exists(eid) is False, \
        "blob не видалений одразу після ACK — README-обіцянка порушена"


async def test_dm_pending_set_cleaned_up(redis):
    eid = "bb" * 32
    await q.enqueue_envelope(redis, **_mk(eid))
    assert await redis.exists(q._pending_recipients_key(eid))

    await q.acknowledge_envelope(redis, RECIPIENT, eid)
    assert not await redis.exists(q._pending_recipients_key(eid))


# ── Група: видалення лише після ОСТАННЬОГО ACK ────────────────────────────
async def test_group_blob_survives_until_last_ack(redis):
    """
    ГОЛОВНИЙ ТЕСТ. Троє одержувачів, один спільний blob. Перші два ACK
    не повинні видаляти файл — треті учасники ще чекають.
    """
    eid = "cc" * 32
    r1, r2, r3 = "aa" * 32, "bb" * 32, "cc" * 32
    await blob_storage.write_blob(eid, b"group-secret")
    await q.enqueue_envelope_for_recipients(
        redis=redis, envelope_id=eid, sender_pubkey_hex=SENDER,
        recipient_pubkeys_hex=[r1, r2, r3],
        timestamp=int(time.time()), ttl_seconds=3600,
        signature_hex="ff" * 64, hard_ceiling_seconds=86400,
        group_id="group-1",
    )

    await q.acknowledge_envelope(redis, r1, eid)
    await _wait_for_task_completion()
    assert await blob_storage.blob_exists(eid) is True, \
        "blob видалений передчасно — r2/r3 ще не забрали"

    await q.acknowledge_envelope(redis, r2, eid)
    await _wait_for_task_completion()
    assert await blob_storage.blob_exists(eid) is True, \
        "blob видалений передчасно — r3 ще не забрав"

    await q.acknowledge_envelope(redis, r3, eid)
    await _wait_for_task_completion()
    assert await blob_storage.blob_exists(eid) is False, \
        "blob НЕ видалений після ОСТАННЬОГО ACK"
    assert await q.envelope_exists(redis, eid) is False


async def test_group_ack_order_does_not_matter(redis):
    """Контроль: ACK у довільному порядку дає той самий результат —
    видалення на останньому, незалежно від того, хто саме останній."""
    eid = "dd" * 32
    r1, r2 = "11" * 32, "22" * 32
    await blob_storage.write_blob(eid, b"order-test")
    await q.enqueue_envelope_for_recipients(
        redis=redis, envelope_id=eid, sender_pubkey_hex=SENDER,
        recipient_pubkeys_hex=[r1, r2],
        timestamp=int(time.time()), ttl_seconds=3600,
        signature_hex="ff" * 64, hard_ceiling_seconds=86400,
        group_id="group-2",
    )
    await q.acknowledge_envelope(redis, r2, eid)  # другий ACK-ує першим
    await _wait_for_task_completion()
    assert await blob_storage.blob_exists(eid) is True

    await q.acknowledge_envelope(redis, r1, eid)
    await _wait_for_task_completion()
    assert await blob_storage.blob_exists(eid) is False


# ── Справжня паралельна гонка (кілька одночасних ACK на групу) ──────────
async def test_concurrent_group_acks_delete_exactly_once(redis):
    """
    ГОЛОВНИЙ ТЕСТ атомарності. П'ять одержувачів ACK-ають одночасно —
    рівно ОДИН з п'яти EVAL-викликів має отримати сигнал "видали blob"
    (result==1), а не жоден і не кілька. Без атомарного decrement
    паралельні SCARD-читання могли б усі побачити >0 і жоден не
    видалити (protunj) — чи, гірше, гонка могла б дати помилковий
    подвійний виклик secure_delete_blob.
    """
    eid = "ee" * 32
    recipients = [f"{i:064x}" for i in range(5)]
    await blob_storage.write_blob(eid, b"race-test")
    await q.enqueue_envelope_for_recipients(
        redis=redis, envelope_id=eid, sender_pubkey_hex=SENDER,
        recipient_pubkeys_hex=recipients,
        timestamp=int(time.time()), ttl_seconds=3600,
        signature_hex="ff" * 64, hard_ceiling_seconds=86400,
        group_id="group-race",
    )

    results = await asyncio.gather(*[
        redis.eval(
            q._ACK_PENDING_LUA, 2,
            q._pending_recipients_key(eid), q._envelope_meta_key(eid),
            r,
        )
        for r in recipients
    ])

    ones = [r for r in results if r == 1]
    assert len(ones) == 1, \
        f"очікували рівно один сигнал видалення, отримали {len(ones)}: {results}"


# ── Legacy fallback: конверт без pending-tracking ─────────────────────────
async def test_legacy_envelope_without_pending_set_falls_back_safely(redis):
    """
    ГОЛОВНИЙ ТЕСТ безпеки. Конверт, поставлений у чергу СТАРОЮ версією
    коду (без pending SET) — ACK не повинен ні впасти, ні хибно
    трактувати "немає SET" як "усі забрали" (це видалило б meta/blob
    передчасно для групового конверта, де інші учасники ще реально
    чекають). Стара поведінка (reaper як safety net) має продовжувати
    працювати без змін.
    """
    eid = "ff" * 32
    now = int(time.time())
    await redis.zadd(q._inbox_key(RECIPIENT), {eid: now + 3600})
    await redis.set(
        q._envelope_meta_key(eid), b'{"envelope_id": "legacy"}', ex=3600,
    )
    # СВІДОМО не створюємо pending SET — імітує конверт до деплою фіксу.
    await blob_storage.write_blob(eid, b"legacy-blob")

    result = await q.acknowledge_envelope(redis, RECIPIENT, eid)
    await asyncio.sleep(0.05)

    assert result is True, "ACK сам по собі мав спрацювати (inbox прибрано)"
    assert await q.envelope_exists(redis, eid) is True, \
        "meta НЕ мала зникнути для legacy-конверта без pending-tracking"
    assert await blob_storage.blob_exists(eid) is True, \
        "blob НЕ мав зникнути для legacy-конверта без pending-tracking"


# ── Повторний ACK (idempotency) ───────────────────────────────────────────
async def test_double_ack_is_safe(redis):
    """Повторний ACK того самого конверта (наприклад ретрай клієнта) не
    повинен падати чи повторно намагатись видалити вже видалений blob."""
    eid = "12" * 32
    await blob_storage.write_blob(eid, b"double-ack-test")
    await q.enqueue_envelope(redis, **_mk(eid))

    first = await q.acknowledge_envelope(redis, RECIPIENT, eid)
    await _wait_for_task_completion()
    second = await q.acknowledge_envelope(redis, RECIPIENT, eid)

    assert first is True
    assert second is False, "повторний ACK на вже прибраний inbox-запис"
    assert await blob_storage.blob_exists(eid) is False
