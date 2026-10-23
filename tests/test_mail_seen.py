"""
Пошта після повторного входу (відкритий баг): листи не ack-аються
(мультидевайс), локальна скринька стирається при виході — після входу
всі листи за 7 діб поверталися «непрочитаними». mark_mail_seen ставить
флаг у meta, list_inbox його віддає.
"""
from __future__ import annotations

import time

import pytest
from pydantic import ValidationError

from morok_relay import queue as q
from morok_relay.api.messages import MailSeenRequest, mail_seen

pytestmark = pytest.mark.asyncio

OWNER = "22" * 32
OTHER = "33" * 32


async def _enqueue(redis, eid, to=OWNER, channel="mail"):
    await q.enqueue_envelope(
        redis,
        envelope_id=eid,
        sender_pubkey_hex="",
        recipient_pubkey_hex=to,
        timestamp=int(time.time()),
        ttl_seconds=3600,
        signature_hex="",
        hard_ceiling_seconds=3600,
        channel=channel,
        mail_origin="external" if channel == "mail" else None,
    )


async def test_seen_flag_survives_in_inbox_listing(redis, fake_session):
    eid = "a1" * 32
    await _enqueue(redis, eid)
    ttl_before = await redis.ttl(q._envelope_meta_key(eid))
    r = await mail_seen(MailSeenRequest(envelope_ids=[eid]), fake_session(OWNER), redis)
    assert r == {"marked": 1}
    items = await q.list_inbox(redis, OWNER)
    assert items[0]["mail_seen"] is True
    assert items[0]["channel"] == "mail"
    # строк життя не продовжено і не скинуто
    ttl_after = await redis.ttl(q._envelope_meta_key(eid))
    assert 0 < ttl_after <= ttl_before


async def test_cannot_mark_someone_elses_mail(redis, fake_session):
    eid = "a2" * 32
    await _enqueue(redis, eid, to=OTHER)
    r = await mail_seen(MailSeenRequest(envelope_ids=[eid]), fake_session(OWNER), redis)
    assert r == {"marked": 0}
    items = await q.list_inbox(redis, OTHER)
    assert "mail_seen" not in items[0]


async def test_ignores_non_mail_envelopes(redis, fake_session):
    eid = "a3" * 32
    await _enqueue(redis, eid, channel=None)
    r = await mail_seen(MailSeenRequest(envelope_ids=[eid]), fake_session(OWNER), redis)
    assert r == {"marked": 0}


async def test_acked_mail_is_not_resurrected(redis, fake_session):
    eid = "a4" * 32
    await _enqueue(redis, eid)
    await q.acknowledge_envelope(redis, OWNER, eid)
    r = await mail_seen(MailSeenRequest(envelope_ids=[eid]), fake_session(OWNER), redis)
    assert r == {"marked": 0}
    assert await redis.get(q._envelope_meta_key(eid)) is None


async def test_idempotent(redis, fake_session):
    eid = "a5" * 32
    await _enqueue(redis, eid)
    for _ in range(2):
        r = await mail_seen(MailSeenRequest(envelope_ids=[eid, eid]), fake_session(OWNER), redis)
        assert r == {"marked": 1}


async def test_malformed_ids_rejected():
    with pytest.raises(ValidationError):
        MailSeenRequest(envelope_ids=["../etc"])
    with pytest.raises(ValidationError):
        MailSeenRequest(envelope_ids=["AA" * 32])
    with pytest.raises(ValidationError):
        MailSeenRequest(envelope_ids=[])
