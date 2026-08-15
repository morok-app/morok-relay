"""
Фікси за зовнішнім аудитом №2 (lifecycle даних і семантика довіри).

Покривається:
  * federation queue: payload зануляється при SUCCEEDED, завершені
    рядки прибираються cleanup'ом (раніше — ВІЧНИЙ архів ciphertext +
    графа «хто→кому→коли→через що»);
  * абсолютна стеля сесії: вкрадений bearer більше не живе вічно на
    sliding-вікні (корінь проблеми «DMS ніколи не спрацює»);
  * KDF-мінімуми на бекап seed'а: сервер відмовляється зберігати
    перебираємий бекап;
  * ефемерна добова сіль login-журналу: ретроспективна компрометація
    сервера не відкриває хеші минулих днів;
  * exception handler маскує capability-токени в шляху.
"""
from __future__ import annotations

import time
import uuid

import pytest
from sqlalchemy import select

from morok_relay import sessions as ss
from morok_relay.cleanup import (
    FED_DEAD_LETTER_RETENTION_SECONDS,
    FED_SUCCEEDED_RETENTION_SECONDS,
    reap_federation_queue,
)
from morok_relay.models import FederationOutboundQueue, FedQueueStatus
from morok_relay.schemas import BackupCreateRequest

pytestmark = pytest.mark.asyncio


# ── federation queue lifecycle ───────────────────────────────────────────
def _fed_row(status, *, age=0, payload=None):
    now = int(time.time())
    return FederationOutboundQueue(
        id=uuid.uuid4(),
        envelope_id="ab" * 32,
        envelope_data=payload if payload is not None else {"blob": "x" * 64},
        target_relay="relay2.example.com",
        status=status,
        attempts=1,
        next_attempt_at=now - age,
        created_at=now - age,
        delivered_at=(now - age) if status == FedQueueStatus.SUCCEEDED else None,
    )


async def test_cleanup_removes_old_succeeded_rows(db):
    old = _fed_row(FedQueueStatus.SUCCEEDED,
                   age=FED_SUCCEEDED_RETENTION_SECONDS + 100, payload={})
    fresh = _fed_row(FedQueueStatus.SUCCEEDED, age=60, payload={})
    db.add(old)
    db.add(fresh)
    await db.commit()

    removed = await reap_federation_queue(db)
    await db.commit()
    assert removed == 1

    left = (await db.execute(select(FederationOutboundQueue))).scalars().all()
    assert len(left) == 1 and left[0].id == fresh.id


async def test_cleanup_removes_expired_dead_letters_with_payload(db):
    dead = _fed_row(FedQueueStatus.DEAD_LETTER,
                    age=FED_DEAD_LETTER_RETENTION_SECONDS + 100)
    db.add(dead)
    await db.commit()
    removed = await reap_federation_queue(db)
    await db.commit()
    assert removed == 1


async def test_cleanup_never_touches_pending_or_inflight(db):
    """PENDING/IN_FLIGHT — живі доставки, їх не чіпаємо ні за який вік."""
    db.add(_fed_row(FedQueueStatus.PENDING, age=10 * 86400))
    db.add(_fed_row(FedQueueStatus.IN_FLIGHT, age=10 * 86400))
    await db.commit()
    removed = await reap_federation_queue(db)
    await db.commit()
    assert removed == 0
    left = (await db.execute(select(FederationOutboundQueue))).scalars().all()
    assert len(left) == 2


async def test_mark_succeeded_scrubs_payload(pg_sessionmaker, monkeypatch):
    """Після успішної доставки в JSONB лишається порожній dict."""
    from morok_relay.scripts.federation_worker import mark_succeeded

    async with pg_sessionmaker() as db:
        row = _fed_row(FedQueueStatus.PENDING)
        db.add(row)
        await db.commit()
        rid = row.id

    async with pg_sessionmaker() as db:
        row = await db.get(FederationOutboundQueue, rid)
        await mark_succeeded(db, row)

    async with pg_sessionmaker() as db:
        row = await db.get(FederationOutboundQueue, rid)
        assert row.status == FedQueueStatus.SUCCEEDED
        assert row.envelope_data == {}, "ciphertext лишився в БД після доставки"


# ── абсолютна стеля сесії ────────────────────────────────────────────────
async def test_session_dies_at_absolute_cap_despite_activity(redis, monkeypatch):
    """
    ГОЛОВНЕ: sliding-вікно більше не робить токен вічним. Сесія, видана
    31 день тому, мертва навіть якщо нею користувались щодня.
    """
    s = await ss.create_session(redis, "aa" * 32)
    # verify живої — ок
    assert await ss.verify_session_token(redis, s.token) is not None

    # пересуваємо created_at у минуле за стелю
    import hashlib
    digest = hashlib.sha256(s.token.encode()).hexdigest()
    key = f"morok:session:{digest}"
    old_created = int(time.time()) - ss.SESSION_ABSOLUTE_MAX_SECONDS - 100
    await redis.set(key, f"{'aa' * 32}|{old_created}".encode(), ex=3600)

    assert await ss.verify_session_token(redis, s.token) is None, \
        "сесія пережила абсолютну стелю"
    assert not await redis.exists(key), "мертвий ключ не прибрано"


async def test_fresh_session_survives_and_slides(redis):
    s = await ss.create_session(redis, "bb" * 32)
    for _ in range(3):
        assert await ss.verify_session_token(redis, s.token) is not None


# ── KDF-мінімуми ─────────────────────────────────────────────────────────
def _backup_body(**kdf):
    import base64
    return dict(
        encrypted_seed_b64=base64.b64encode(b"\x01" * 64).decode(),
        kdf_salt_b64=base64.b64encode(b"\x02" * 16).decode(),
        kdf_params=kdf,
        schema_version=1,
    )


async def test_backup_rejects_weak_or_unknown_kdf():
    for weak in (
        {},                                            # не задекларовано
        {"alg": "pbkdf2", "m": 65536, "t": 3},         # не argon2id
        {"alg": "argon2id", "m": 1024, "t": 3},        # мало пам'яті
        {"alg": "argon2id", "m": 65536, "t": 1},       # мало ітерацій
    ):
        with pytest.raises(ValueError):
            BackupCreateRequest(**_backup_body(**weak))


async def test_backup_accepts_strong_kdf():
    req = BackupCreateRequest(
        **_backup_body(alg="argon2id", m=65536, t=3, p=1)
    )
    assert req.kdf_params["alg"] == "argon2id"
    # альтернативні назви полів теж приймаються
    BackupCreateRequest(
        **_backup_body(algorithm="argon2id", memory_kib=131072, iterations=2)
    )


# ── ефемерна сіль login-журналу ──────────────────────────────────────────
async def test_daily_salt_is_random_and_stored_with_ttl(redis):
    from morok_relay.api.auth import _daily_ip_hash

    h1 = await _daily_ip_hash(redis, "1.2.3.4")
    h2 = await _daily_ip_hash(redis, "1.2.3.4")
    h3 = await _daily_ip_hash(redis, "5.6.7.8")
    assert h1 == h2, "групування в межах доби зламано"
    assert h1 != h3

    keys = [k async for k in redis.scan_iter("morok:login_salt:*")]
    assert len(keys) == 1
    ttl = await redis.ttl(keys[0])
    assert 0 < ttl <= 48 * 3600, "сіль без TTL — ретроспективно відновна"

    # сіль ВИПАДКОВА: замінюємо — хеш того ж IP змінюється
    await redis.set(keys[0], b"\x00" * 32, ex=3600)
    h4 = await _daily_ip_hash(redis, "1.2.3.4")
    assert h4 != h1, "хеш не залежить від збереженої солі (детермінований?)"


# ── sanitizer на шляху винятків ──────────────────────────────────────────
async def test_exception_log_path_is_sanitized():
    """Пряма перевірка: burner-токен у шляху маскується санітайзером,
    і саме санітайзер використано в unhandled_exception_handler."""
    import inspect

    from morok_relay.main import _sanitize_path, unhandled_exception_handler

    assert _sanitize_path("/api/v1/burner/SECRET-TOKEN/send") == \
        "/api/v1/burner/***/send"
    src = inspect.getsource(unhandled_exception_handler)
    assert "_sanitize_path" in src, \
        "exception handler логує сирий шлях — capability-токени течуть у журнал"
