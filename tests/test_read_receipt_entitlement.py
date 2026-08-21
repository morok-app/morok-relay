"""
Read receipt entitlement (жорсткий свіжий прохід, MEDIUM з фрешевого
аудиту).

Знахідка: /messages/read приймав envelope_id від клієнта і не
перевіряв, чи цей конверт узагалі був адресований саме цьому reader'у
(bearer, а тепер навіть підпис reader'а, доводить лише "хто підписав
receipt", не "чи envelope Y справді був повідомленням цьому X"). Bearer
міг надіслати "прочитано" для довільного, ЧУЖОГО envelope_id — не
витік plaintext, але фальшива галочка для sender'а.

Фікс: delivery tombstone, записаний у acknowledge_envelope на кожному
реальному ACK, окремо від pending-recipient/blob-lifecycle механізму
(щоб пережити негайне видалення meta після ACK — HIGH#3 фікс).
post_read_receipts перевіряє tombstone перед прийняттям receipt.
"""
from __future__ import annotations

import time

import pytest

from morok_relay.queue import (
    acknowledge_envelope,
    enqueue_envelope,
    was_delivered_to,
)

pytestmark = pytest.mark.asyncio

SENDER = "11" * 32
READER = "22" * 32
STRANGER = "33" * 32


async def _deliver(redis, eid: str, recipient: str = READER) -> None:
    await enqueue_envelope(
        redis, envelope_id=eid, sender_pubkey_hex=SENDER,
        recipient_pubkey_hex=recipient, timestamp=int(time.time()),
        ttl_seconds=3600, signature_hex="ff" * 64,
        hard_ceiling_seconds=86400,
    )


# ── was_delivered_to: чиста логіка ────────────────────────────────────────
async def test_was_delivered_to_false_before_ack(redis):
    eid = "aa" * 32
    await _deliver(redis, eid)
    assert await was_delivered_to(redis, eid, READER) is False


async def test_was_delivered_to_true_after_ack(redis):
    eid = "bb" * 32
    await _deliver(redis, eid)
    await acknowledge_envelope(redis, READER, eid)
    assert await was_delivered_to(redis, eid, READER) is True


async def test_was_delivered_to_false_for_fabricated_envelope(redis):
    """ГОЛОВНИЙ ТЕСТ. Конверт, який ніколи не існував і ніколи не
    доставлявся — was_delivered_to не бреше "так" на вигадку."""
    assert await was_delivered_to(redis, "cc" * 32, READER) is False


async def test_was_delivered_to_false_for_different_reader(redis):
    """Конверт доставлено READER'у — STRANGER не має tombstone для
    нього, навіть якщо знає точний envelope_id."""
    eid = "dd" * 32
    await _deliver(redis, eid, recipient=READER)
    await acknowledge_envelope(redis, READER, eid)
    assert await was_delivered_to(redis, eid, STRANGER) is False


async def test_tombstone_survives_meta_deletion(redis):
    """ГОЛОВНИЙ ТЕСТ на сумісність із HIGH#3 фіксом. Meta видаляється
    ОДРАЗУ на ACK (для DM) — tombstone має пережити це видалення,
    інакше легітимний reader не зміг би підтвердити прочитання
    власного повідомлення."""
    from morok_relay.queue import envelope_exists

    eid = "ee" * 32
    await _deliver(redis, eid)
    await acknowledge_envelope(redis, READER, eid)

    assert await envelope_exists(redis, eid) is False, \
        "тестова передумова: meta мала зникнути одразу (HIGH#3)"
    assert await was_delivered_to(redis, eid, READER) is True, \
        "tombstone не пережив видалення meta — легітимний reader " \
        "не зможе підтвердити власне прочитання"


# ── наскрізно через post_read_receipts ────────────────────────────────────
async def test_receipt_for_fabricated_envelope_is_skipped(db, redis):
    """
    ГОЛОВНИЙ ТЕСТ наскрізно — суть знахідки. Reader надсилає receipt
    для envelope_id, який йому НІКОЛИ не доставлявся (вигаданий чи
    чужий) — сервер має відхилити, а не переслати фальшиву галочку
    sender'у.
    """
    from morok_relay.api.messages import ReadReceiptItem, ReadReceiptsRequest, post_read_receipts
    from morok_relay.config import get_settings
    from morok_relay.models import User, UserTier
    from morok_relay.sessions import Session

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(SENDER), username="alice",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()

    session = Session(token="t" * 64, pubkey_hex=READER, expires_at=2**31)
    body = ReadReceiptsRequest(reads=[
        ReadReceiptItem(
            envelope_id="ff" * 32,  # ніколи не доставлявся READER'у
            sender_pubkey_hex=SENDER,
        ),
    ])
    result = await post_read_receipts(body, session, db, redis)
    assert result["sent"] == 0
    assert result["skipped"] == 1


async def test_receipt_for_someone_elses_envelope_is_skipped(db, redis):
    """STRANGER намагається підтвердити прочитання конверта, який
    реально був доставлений READER'у, не йому."""
    from morok_relay.api.messages import ReadReceiptItem, ReadReceiptsRequest, post_read_receipts
    from morok_relay.config import get_settings
    from morok_relay.models import User, UserTier
    from morok_relay.sessions import Session

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(SENDER), username="dave",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()

    eid = "12" * 32
    await _deliver(redis, eid, recipient=READER)
    await acknowledge_envelope(redis, READER, eid)

    stranger_session = Session(
        token="t" * 64, pubkey_hex=STRANGER, expires_at=2**31,
    )
    body = ReadReceiptsRequest(reads=[
        ReadReceiptItem(envelope_id=eid, sender_pubkey_hex=SENDER),
    ])
    result = await post_read_receipts(body, stranger_session, db, redis)
    assert result["sent"] == 0
    assert result["skipped"] == 1


async def test_legitimate_receipt_still_works_after_delivery(db, redis):
    """Контроль: справжній reader, що реально отримав і ACK-нув
    повідомлення, досі може підтвердити прочитання нормально."""
    from morok_relay.api.messages import ReadReceiptItem, ReadReceiptsRequest, post_read_receipts
    from morok_relay.config import get_settings
    from morok_relay.models import User, UserTier
    from morok_relay.sessions import Session

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(SENDER), username="erin",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()

    eid = "34" * 32
    await _deliver(redis, eid, recipient=READER)
    await acknowledge_envelope(redis, READER, eid)

    session = Session(token="t" * 64, pubkey_hex=READER, expires_at=2**31)
    body = ReadReceiptsRequest(reads=[
        ReadReceiptItem(envelope_id=eid, sender_pubkey_hex=SENDER),
    ])
    result = await post_read_receipts(body, session, db, redis)
    assert result["sent"] == 1
    assert result["skipped"] == 0
