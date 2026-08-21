"""
Orphan blob на reject-path (жорсткий свіжий прохід — зовнішній
перегляд другого раунду).

Знахідка: write_blob() записує ciphertext на диск ПЕРЕД викликом
enqueue_envelope(). Якщо inbox одержувача повний (429) чи Redis
тимчасово недоступний (503), enqueue_envelope() кидає EnqueueRejected
— файл уже записаний лишається сиротою до найближчого reaper-проходу.
Не catastrophic (256 KiB на конверт, 60/хв на pubkey), але це
компенсація постфактум, а не нормальний lifecycle.

Фікс: write_blob_then_enqueue() — спільний helper (не дублювання в
п'яти місцях виклику: messages.py, mail.py, sealed.py, burner.py,
federation.py remote-DM-forward) — при EnqueueRejected видаляє щойно
записаний файл одразу, перш ніж прокинути той самий виняток далі
(клієнт і далі отримує 429/503, семантика відповіді не змінюється).
"""
from __future__ import annotations

import time

import pytest
from fastapi import HTTPException

from morok_relay import blob_storage
from morok_relay import queue as q

pytestmark = pytest.mark.asyncio

SENDER = "11" * 32
RECIPIENT = "22" * 32


def _mk(eid: str) -> dict:
    return dict(
        sender_pubkey_hex=SENDER,
        recipient_pubkey_hex=RECIPIENT,
        timestamp=int(time.time()),
        ttl_seconds=3600,
        signature_hex="ff" * 64,
        hard_ceiling_seconds=86400,
    )


# ── write_blob_then_enqueue: чиста логіка ────────────────────────────────
async def test_success_path_keeps_blob(redis):
    """Контроль: коли enqueue успішний, blob лишається — helper нічого
    не видаляє даремно."""
    eid = "aa" * 32
    expires_at = await q.write_blob_then_enqueue(
        eid, b"normal-message", redis=redis, **_mk(eid),
    )
    assert expires_at is not None
    assert await blob_storage.blob_exists(eid) is True


async def test_full_inbox_rejection_removes_orphan_blob(redis, monkeypatch):
    """
    ГОЛОВНИЙ ТЕСТ — рівно той сценарій, що просив зовнішній перегляд:
    full inbox → send → 429 → файл відсутній.
    """
    monkeypatch.setattr(q, "MAX_INBOX_QUEUE_DEPTH", 1)
    # Заповнюємо inbox одержувача до відмови.
    now = int(time.time())
    await redis.zadd(f"morok:inbox:{RECIPIENT}", {"existing-envelope": now + 3600})

    eid = "bb" * 32
    with pytest.raises(q.EnqueueRejected) as e:
        await q.write_blob_then_enqueue(
            eid, b"rejected-message", redis=redis, **_mk(eid),
        )
    assert e.value.status_code == 429

    assert await blob_storage.blob_exists(eid) is False, \
        "blob лишився сиротою на диску після відхиленого enqueue"


async def test_redis_failure_rejection_removes_orphan_blob(redis, monkeypatch):
    """Той самий принцип для 503-шляху (Redis тимчасово недоступний під
    час enqueue), не лише 429 (full inbox)."""
    async def boom(*a, **kw):
        raise ConnectionError("redis down")

    monkeypatch.setattr(redis, "eval", boom)

    eid = "cc" * 32
    with pytest.raises(q.EnqueueRejected) as e:
        await q.write_blob_then_enqueue(
            eid, b"redis-down-message", redis=redis, **_mk(eid),
        )
    assert e.value.status_code == 503
    assert await blob_storage.blob_exists(eid) is False


async def test_orphan_cleanup_failure_does_not_mask_original_error(
    redis, monkeypatch,
):
    """
    Якщо саме ВИДАЛЕННЯ (secure_delete_blob) теж падає — оригінальний
    EnqueueRejected усе одно долітає до клієнта (429/503), не
    ховається за помилкою cleanup'у. Reaper full-scan підхопить файл
    пізніше як safety net.
    """
    monkeypatch.setattr(q, "MAX_INBOX_QUEUE_DEPTH", 1)
    now = int(time.time())
    await redis.zadd(f"morok:inbox:{RECIPIENT}", {"existing": now + 3600})

    async def boom_delete(*a, **kw):
        raise OSError("disk full, can't even delete")

    monkeypatch.setattr(q, "secure_delete_blob", boom_delete)

    eid = "dd" * 32
    with pytest.raises(q.EnqueueRejected) as e:
        await q.write_blob_then_enqueue(
            eid, b"cleanup-fails-too", redis=redis, **_mk(eid),
        )
    assert e.value.status_code == 429, \
        "cleanup-помилка замаскувала оригінальний EnqueueRejected"


# ── наскрізно через реальний HTTP-ендпоінт ────────────────────────────────
async def test_send_envelope_endpoint_cleans_orphan_on_full_inbox(
    db, redis, monkeypatch,
):
    """
    Наскрізний тест — рівно сценарій із запиту: POST /messages → 429 →
    blob file absent, через реальний send_envelope(), не напряму
    write_blob_then_enqueue().
    """
    import nacl.signing

    from morok_relay import crypto
    from morok_relay.api.messages import send_envelope
    from morok_relay.config import get_settings
    from morok_relay.models import User, UserTier
    from morok_relay.schemas import EnvelopeIn
    from morok_relay.sessions import Session

    monkeypatch.setattr(q, "MAX_INBOX_QUEUE_DEPTH", 1)

    settings = get_settings()
    now = int(time.time())
    seed = b"\x55" * 32
    sk = nacl.signing.SigningKey(seed)
    sender_hex = sk.verify_key.encode().hex()

    db.add(User(pubkey=bytes.fromhex(sender_hex), username="alice",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    db.add(User(pubkey=bytes.fromhex(RECIPIENT), username="bob",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()

    # Заповнюємо inbox одержувача.
    await redis.zadd(f"morok:inbox:{RECIPIENT}", {"existing": now + 3600})

    import base64
    blob_b64 = base64.b64encode(b"\x01" * 20).decode()
    ts = now
    unsigned = {"from": sender_hex, "to": RECIPIENT, "ts": ts,
                "ttl": 3600, "blob": blob_b64}
    sig = crypto.ed25519_sign(
        crypto.canonical_json(unsigned), bytes(sk._seed),
    ).hex()

    body = EnvelopeIn(
        from_=sender_hex, to=RECIPIENT, ts=ts, ttl=3600,
        blob=blob_b64, sig=sig,
    )
    session = Session(token="t" * 64, pubkey_hex=sender_hex, expires_at=2**31)

    with pytest.raises(HTTPException) as e:
        await send_envelope(body, session, db, redis)
    assert e.value.status_code == 429

    # Той самий детермінований hash, що send_envelope обчислює
    # всередині: sha256(sender||recipient||ts_be8||sha256(blob)).
    # Перевіряємо КОНКРЕТНИЙ файл, не всю blob_dir — вона спільна для
    # всієї тестової сесії й уже містить файли з інших тестів.
    import hashlib as _hashlib
    h = _hashlib.sha256()
    h.update(bytes.fromhex(sender_hex))
    h.update(bytes.fromhex(RECIPIENT))
    h.update(ts.to_bytes(8, "big"))
    h.update(_hashlib.sha256(base64.b64decode(blob_b64)).digest())
    envelope_id = h.hexdigest()

    assert await blob_storage.blob_exists(envelope_id) is False, \
        "осиротілий blob лишився на диску після 429"
