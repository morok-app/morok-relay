"""
Read receipt: опціональний Ed25519-підпис reader'а (аудит зовн. №4,
MEDIUM).

Знахідка: код чесно документував ризик — read receipts unsigned,
недобросовісний federation peer міг вигадати "user X read this",
результат — фальшива галочка (не розкриття plaintext). Повний фікс
(клієнт підписує) вимагає клієнтських змін, тому тут — паралельний
опціональний шлях: якщо клієнт передає reader_signature_hex+signed_at,
local relay перевіряє (bearer уже автентифікує reader локально, підпис
тут — підготовка для forward) і передає підпис далі; приймаючий relay
перевіряє НЕЗАЛЕЖНО, не довіряючи forwarding relay на слово. Legacy
(unsigned) шлях працює як і раніше — жодного клієнта не ламаємо.
"""
from __future__ import annotations

import time

import nacl.signing
import pytest
from fastapi import HTTPException

from morok_relay.api.messages import (
    ReadReceiptItem,
    ReadReceiptsRequest,
    _verify_read_receipt_signature,
)
from morok_relay.crypto import canonical_json, ed25519_sign
from morok_relay.models import User, UserTier
from morok_relay.sessions import Session

pytestmark = pytest.mark.asyncio

_SEED = b"\x51" * 32
_SK = nacl.signing.SigningKey(_SEED)
READER = _SK.verify_key.encode().hex()
SENDER = "22" * 32


def _sign(envelope_id: str, sender: str, group_id: str | None, ts: int) -> str:
    msg = canonical_json({
        "morok_read_receipt": "morok_read_receipt:v1",
        "envelope_id": envelope_id,
        "sender_pubkey_hex": sender,
        "reader_pubkey_hex": READER,
        "group_id": group_id,
        "signed_at": ts,
    })
    return ed25519_sign(msg, bytes(_SK._seed)).hex()


# ── чиста функція верифікації ────────────────────────────────────────────
def test_valid_signature_accepted():
    eid = "aa" * 32
    ts = int(time.time())
    sig = _sign(eid, SENDER, None, ts)
    assert _verify_read_receipt_signature(
        envelope_id=eid, sender_pubkey_hex=SENDER, reader_pubkey_hex=READER,
        group_id=None, signed_at=ts, signature_hex=sig,
    ) is True


def test_forged_signature_rejected():
    eid = "aa" * 32
    ts = int(time.time())
    assert _verify_read_receipt_signature(
        envelope_id=eid, sender_pubkey_hex=SENDER, reader_pubkey_hex=READER,
        group_id=None, signed_at=ts, signature_hex="00" * 64,
    ) is False


def test_signature_for_different_envelope_rejected():
    """Підпис валідний для ІНШОГО envelope_id — не має пройти для цього."""
    ts = int(time.time())
    sig = _sign("aa" * 32, SENDER, None, ts)
    assert _verify_read_receipt_signature(
        envelope_id="bb" * 32, sender_pubkey_hex=SENDER,
        reader_pubkey_hex=READER, group_id=None, signed_at=ts,
        signature_hex=sig,
    ) is False


def test_stale_signed_at_rejected():
    eid = "aa" * 32
    old_ts = int(time.time()) - 400
    sig = _sign(eid, SENDER, None, old_ts)
    assert _verify_read_receipt_signature(
        envelope_id=eid, sender_pubkey_hex=SENDER, reader_pubkey_hex=READER,
        group_id=None, signed_at=old_ts, signature_hex=sig,
    ) is False


def test_group_id_bound_into_signature():
    """Підпис без group_id не годиться для receipt З group_id."""
    eid = "aa" * 32
    ts = int(time.time())
    sig = _sign(eid, SENDER, None, ts)
    assert _verify_read_receipt_signature(
        envelope_id=eid, sender_pubkey_hex=SENDER, reader_pubkey_hex=READER,
        group_id="some-group", signed_at=ts, signature_hex=sig,
    ) is False


# ── схема: обидва поля опціональні, разом чи відсутні ────────────────────
def test_schema_accepts_unsigned_legacy_item():
    item = ReadReceiptItem(envelope_id="aa" * 32, sender_pubkey_hex=SENDER)
    assert item.reader_signature_hex is None
    assert item.signed_at is None


def test_schema_accepts_signed_item():
    ts = int(time.time())
    item = ReadReceiptItem(
        envelope_id="aa" * 32, sender_pubkey_hex=SENDER,
        reader_signature_hex="ff" * 64, signed_at=ts,
    )
    assert item.reader_signature_hex == "ff" * 64


def test_schema_rejects_malformed_signature_hex():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ReadReceiptItem(
            envelope_id="aa" * 32, sender_pubkey_hex=SENDER,
            reader_signature_hex="not-hex", signed_at=int(time.time()),
        )


# ── наскрізно через post_read_receipts (локальний шлях) ──────────────────
async def test_post_read_receipts_forged_signature_skipped(db, redis):
    """
    ГОЛОВНИЙ ТЕСТ. Клієнт НАМАГАВСЯ підписати, але підпис невалідний —
    елемент пропускається (skipped), а НЕ мовчки приймається як
    unsigned. Мовчазний даунгрейд ховав би від клієнта, що щось
    зламалось.
    """
    from morok_relay.api.messages import post_read_receipts
    from morok_relay.config import get_settings

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(SENDER), username="alice",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()

    session = Session(token="t" * 64, pubkey_hex=READER, expires_at=2**31)
    body = ReadReceiptsRequest(reads=[
        ReadReceiptItem(
            envelope_id="cc" * 32, sender_pubkey_hex=SENDER,
            reader_signature_hex="00" * 64,  # завідомо невалідний
            signed_at=now,
        ),
    ])
    result = await post_read_receipts(body, session, db, redis)
    assert result["skipped"] == 1
    assert result["sent"] == 0


async def test_post_read_receipts_valid_signature_sent(db, redis):
    from morok_relay.api.messages import post_read_receipts
    from morok_relay.config import get_settings
    from morok_relay.queue import acknowledge_envelope, enqueue_envelope

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(SENDER), username="bob",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()

    # Entitlement-перевірка (жорсткий свіжий прохід) вимагає реального
    # ACK — вигаданий envelope_id без доставки більше не проходить.
    eid = "dd" * 32
    await enqueue_envelope(
        redis, envelope_id=eid, sender_pubkey_hex=SENDER,
        recipient_pubkey_hex=READER, timestamp=now, ttl_seconds=3600,
        signature_hex="ff" * 64, hard_ceiling_seconds=86400,
    )
    await acknowledge_envelope(redis, READER, eid)

    session = Session(token="t" * 64, pubkey_hex=READER, expires_at=2**31)
    sig = _sign(eid, SENDER, None, now)
    body = ReadReceiptsRequest(reads=[
        ReadReceiptItem(
            envelope_id=eid, sender_pubkey_hex=SENDER,
            reader_signature_hex=sig, signed_at=now,
        ),
    ])
    result = await post_read_receipts(body, session, db, redis)
    assert result["sent"] == 1
    assert result["skipped"] == 0


async def test_post_read_receipts_legacy_unsigned_still_works(db, redis):
    """Контроль: клієнт БЕЗ підпису досі працює точно як раніше."""
    from morok_relay.api.messages import post_read_receipts
    from morok_relay.config import get_settings
    from morok_relay.queue import acknowledge_envelope, enqueue_envelope

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(SENDER), username="carol",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()

    eid = "ee" * 32
    await enqueue_envelope(
        redis, envelope_id=eid, sender_pubkey_hex=SENDER,
        recipient_pubkey_hex=READER, timestamp=now, ttl_seconds=3600,
        signature_hex="ff" * 64, hard_ceiling_seconds=86400,
    )
    await acknowledge_envelope(redis, READER, eid)

    session = Session(token="t" * 64, pubkey_hex=READER, expires_at=2**31)
    body = ReadReceiptsRequest(reads=[
        ReadReceiptItem(envelope_id=eid, sender_pubkey_hex=SENDER),
    ])
    result = await post_read_receipts(body, session, db, redis)
    assert result["sent"] == 1


# ── federation-хендлер: незалежна верифікація ─────────────────────────────
async def test_federation_handler_rejects_forged_signature(db, redis):
    from morok_relay.api.federation import _handle_read_receipt
    from morok_relay.config import get_settings

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(SENDER), username="dave",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()

    envelope = {
        "envelope_id": "ff" * 32,
        "sender_pubkey_hex": SENDER,
        "reader_pubkey_hex": READER,
        "group_id": None,
        "reader_signature_hex": "00" * 64,
        "signed_at": now,
    }
    with pytest.raises(HTTPException) as e:
        await _handle_read_receipt(envelope, db, redis, settings)
    assert e.value.status_code == 400
    assert e.value.detail == "read_receipt_invalid_signature"


async def test_federation_handler_accepts_valid_signature(db, redis):
    from morok_relay.api.federation import _handle_read_receipt
    from morok_relay.config import get_settings

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(SENDER), username="erin",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()

    eid = "12" * 32
    sig = _sign(eid, SENDER, None, now)
    envelope = {
        "envelope_id": eid,
        "sender_pubkey_hex": SENDER,
        "reader_pubkey_hex": READER,
        "group_id": None,
        "reader_signature_hex": sig,
        "signed_at": now,
    }
    result = await _handle_read_receipt(envelope, db, redis, settings)
    assert result.accepted is True


async def test_federation_handler_unsigned_still_works(db, redis):
    """Контроль: forwarding relay без підпису — стара unsigned
    поведінка, задокументований і незмінений ризик."""
    from morok_relay.api.federation import _handle_read_receipt
    from morok_relay.config import get_settings

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(SENDER), username="frank",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()

    envelope = {
        "envelope_id": "34" * 32,
        "sender_pubkey_hex": SENDER,
        "reader_pubkey_hex": READER,
        "group_id": None,
    }
    result = await _handle_read_receipt(envelope, db, redis, settings)
    assert result.accepted is True
