"""
Group delivery honesty (аудит зовн. №5, MEDIUM).

Знахідка: enqueue_envelope_for_recipients() правильно рахує реальну
(eligible) кількість вставлених одержувачів — але do_group_fanout()
викликав функцію БЕЗ присвоєння результату (значення відкидалось), а
send_group_message() навіть той приблизний local_count ігнорував на
користь len(group.members)-1. Сервер підтверджував "доставлено N",
коли частину N реально пропущено через переповнений inbox локального
одержувача.
"""
from __future__ import annotations

import time
import uuid

import pytest

from morok_relay import queue as q

pytestmark = pytest.mark.asyncio

SENDER = "11" * 32


def _group(members: list[bytes], gid: uuid.UUID | None = None):
    from morok_relay.models import Group, GroupMember
    gid = gid or uuid.uuid4()
    now = int(time.time())
    g = Group(
        id=gid, creator_pubkey=members[0],
        name_encrypted=b"\x01" * 32, is_channel=False,
        default_ttl_seconds=86400, anonymous_senders=False,
        max_members=50, created_at=now,
    )
    for pk in members:
        g.members.append(GroupMember(
            id=uuid.uuid4(), pubkey=pk, is_admin=(pk == members[0]),
            joined_at=now,
        ))
    return g


def _envelope(gid: str) -> dict:
    return {
        "from": SENDER, "to": gid,
        "ts": int(time.time()), "ttl": 3600,
        "blob": "AAAA", "sig": "ff" * 64,
        "from_username": None,
    }


# ── do_group_fanout: реальна кількість, не запитана ──────────────────────
async def test_fanout_reports_actual_delivered_not_requested(
    db, redis, monkeypatch,
):
    """
    ГОЛОВНИЙ ТЕСТ. Ставимо inbox одного з трьох одержувачів на межу
    ліміту (переповнений) — fanout має чесно повернути 2 доставлених
    з 3 запитаних, а не мовчки 3.
    """
    from morok_relay.api.groups import do_group_fanout

    monkeypatch.setattr(q, "MAX_INBOX_QUEUE_DEPTH", 1)

    sender = bytes.fromhex(SENDER)
    r1, r2, r3 = b"\x02" * 32, b"\x03" * 32, b"\x04" * 32
    group = _group([sender, r1, r2, r3])

    # r2 вже має inbox на межі ліміту — наступний конверт мусить бути
    # пропущений саме для нього.
    now = int(time.time())
    await redis.zadd(f"morok:inbox:{r2.hex()}", {"existing-envelope": now + 3600})

    envelope_id = "ab" * 32
    (
        local_delivered, remote_relay_count,
        remote_recipients, some_skipped,
    ) = await do_group_fanout(
        group=group, envelope=_envelope(str(group.id)),
        envelope_id=envelope_id, db=db, redis=redis,
    )

    assert local_delivered == 2, \
        f"звітувало {local_delivered} доставлених замість реальних 2"
    assert some_skipped is True
    assert remote_relay_count == 0
    assert remote_recipients == 0


async def test_fanout_reports_full_count_when_nothing_skipped(db, redis):
    """Контроль: коли нікого не пропущено, число і прапорець чесні
    в інший бік — full count, skipped=False."""
    from morok_relay.api.groups import do_group_fanout

    sender = bytes.fromhex(SENDER)
    r1, r2 = b"\x05" * 32, b"\x06" * 32
    group = _group([sender, r1, r2])

    local_delivered, _, _, some_skipped = await do_group_fanout(
        group=group, envelope=_envelope(str(group.id)),
        envelope_id="cd" * 32, db=db, redis=redis,
    )
    assert local_delivered == 2
    assert some_skipped is False


# ── наскрізно: GroupEnvelopeAck.recipient_count чесний ───────────────────
async def test_send_group_message_ack_reflects_actual_delivery(
    db, redis, monkeypatch,
):
    """
    Наскрізний тест на саму суть знахідки: клієнтська відповідь
    (GroupEnvelopeAck) більше не бреше про кількість. Раніше тут
    незалежно від переповнення стояло б len(group.members)-1 == 3.
    """
    import base64

    import nacl.signing

    from morok_relay import crypto
    from morok_relay.api.groups import send_group_message
    from morok_relay.schemas import GroupEnvelopeIn
    from morok_relay.sessions import Session

    monkeypatch.setattr(q, "MAX_INBOX_QUEUE_DEPTH", 1)

    seed = b"\x77" * 32
    sk = nacl.signing.SigningKey(seed)
    sender_pk = sk.verify_key.encode()
    sender_hex = sender_pk.hex()

    r1, r2, r3 = b"\x08" * 32, b"\x09" * 32, b"\x0a" * 32
    group = _group([sender_pk, r1, r2, r3])
    db.add(group)
    await db.commit()

    now = int(time.time())
    await redis.zadd(f"morok:inbox:{r2.hex()}", {"existing": now + 3600})

    blob_b64 = base64.b64encode(b"\x01" * 20).decode()
    ts = int(time.time())
    unsigned = {
        "from": sender_hex, "to": str(group.id),
        "ts": ts, "ttl": 3600, "blob": blob_b64,
    }
    canonical = crypto.canonical_json(unsigned)
    sig = crypto.ed25519_sign(canonical, bytes(sk._seed)).hex()

    body = GroupEnvelopeIn(
        from_=sender_hex, to=str(group.id), ts=ts, ttl=3600,
        blob=blob_b64, sig=sig,
    )
    session = Session(token="t" * 64, pubkey_hex=sender_hex, expires_at=2**31)

    ack = await send_group_message(str(group.id), body, session, db, redis)

    assert ack.recipient_count == 2, \
        f"ack каже {ack.recipient_count}, реально доставлено 2 (r2 переповнений)"
    assert ack.some_recipients_skipped is True


async def test_send_group_message_ack_honest_when_all_delivered(db, redis):
    """Контроль наскрізно: коли нікого не пропущено, ack теж чесний
    (і, окремо, збігається з реальною кількістю members-1)."""
    import base64

    import nacl.signing

    from morok_relay import crypto
    from morok_relay.api.groups import send_group_message
    from morok_relay.schemas import GroupEnvelopeIn
    from morok_relay.sessions import Session

    seed = b"\x88" * 32
    sk = nacl.signing.SigningKey(seed)
    sender_pk = sk.verify_key.encode()
    sender_hex = sender_pk.hex()

    r1, r2 = b"\x0b" * 32, b"\x0c" * 32
    group = _group([sender_pk, r1, r2])
    db.add(group)
    await db.commit()

    blob_b64 = base64.b64encode(b"\x01" * 20).decode()
    ts = int(time.time())
    unsigned = {
        "from": sender_hex, "to": str(group.id),
        "ts": ts, "ttl": 3600, "blob": blob_b64,
    }
    sig = crypto.ed25519_sign(
        crypto.canonical_json(unsigned), bytes(sk._seed),
    ).hex()

    body = GroupEnvelopeIn(
        from_=sender_hex, to=str(group.id), ts=ts, ttl=3600,
        blob=blob_b64, sig=sig,
    )
    session = Session(token="t" * 64, pubkey_hex=sender_hex, expires_at=2**31)

    ack = await send_group_message(str(group.id), body, session, db, redis)
    assert ack.recipient_count == 2
    assert ack.some_recipients_skipped is False
