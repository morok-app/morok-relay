"""
Підписаний DMS check-in (аудит зовн. №3, HIGH — bearer як proof-of-life).

Знахідка: generic bearer-активність автоматично bump'ила
last_check_in_at усіх ARMED DMS — тобто викрадений bearer-токен
(навіть у межах 30-денної стелі сесій) міг придушувати DMS до місяця
без жодного доступу до seed/private key.

Фікс не ламає наявний bearer-fallback (клієнти ще не вміють підписувати
heartbeat), а додає ПРАВИЛЬНИЙ паралельний шлях: /dms/checkin-signed,
Ed25519 із domain separation. Тести перевіряють саме цей новий шлях —
bearer-fallback уже покритий test_dms_reaper.py.
"""
from __future__ import annotations

import time

import nacl.signing
import pytest
from fastapi import HTTPException

from morok_relay.api.dms import SignedCheckInRequest, check_in_signed, create_dms
from morok_relay.crypto import canonical_json, ed25519_sign
from morok_relay.models import DeadManSwitch, User, UserTier
from morok_relay.schemas import DMSCreate
from morok_relay.sessions import Session

pytestmark = pytest.mark.asyncio

_SEED = b"\x42" * 32
_SK = nacl.signing.SigningKey(_SEED)
OWNER = _SK.verify_key.encode().hex()


def _sign_checkin(ts: int) -> str:
    msg = canonical_json({
        "morok_dms_checkin": "v1",
        "pubkey": OWNER,
        "timestamp": ts,
    })
    return ed25519_sign(msg, bytes(_SK._seed)).hex()


def _session() -> Session:
    return Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)


async def _ensure_user(db) -> None:
    from sqlalchemy import select

    from morok_relay.config import get_settings
    pk = bytes.fromhex(OWNER)
    existing = (await db.execute(
        select(User).where(User.pubkey == pk)
    )).scalar_one_or_none()
    if existing is None:
        db.add(User(pubkey=pk, tier=UserTier.FREE,
                    home_relay=get_settings().relay_name,
                    created_at=int(time.time()),
                    last_seen_at=int(time.time())))
        await db.commit()


async def _armed_dms(db):
    import base64
    body = DMSCreate(
        trigger_seconds=86400,
        payload_encrypted=base64.b64encode(b"\x01" * 100).decode(),
        recipient_pubkeys_hex=["aa" * 32],
        label=None,
    )
    return await create_dms(body, _session(), db)


# ── ГОЛОВНЕ: валідний підпис проходить, довільний bearer сам по собі не рятує ──
async def test_valid_signature_bumps_checkin(db, redis):
    await _ensure_user(db)
    info = await _armed_dms(db)

    import uuid
    row = await db.get(DeadManSwitch, uuid.UUID(info.dms_id))
    row.last_check_in_at = int(time.time()) - 90000
    await db.commit()

    ts = int(time.time())
    result = await check_in_signed(
        SignedCheckInRequest(timestamp=ts, signature_hex=_sign_checkin(ts)),
        _session(), db, redis,
    )
    assert result.checked_in_count == 1

    await db.refresh(row)
    assert row.last_check_in_at >= ts - 5


async def test_forged_signature_rejected(db, redis):
    """Довільний (невірний) підпис — 401, попри валідний bearer у сесії."""
    await _ensure_user(db)
    ts = int(time.time())
    with pytest.raises(HTTPException) as e:
        await check_in_signed(
            SignedCheckInRequest(timestamp=ts, signature_hex="00" * 64),
            _session(), db, redis,
        )
    assert e.value.status_code == 401
    assert e.value.detail == "invalid_signature"


async def test_signature_for_different_pubkey_rejected(db, redis):
    """
    Підпис валідний, але зроблений ІНШИМ ключем — current.pubkey_hex
    береться з верифікованої сесії, не з тіла запиту, тож підмінити
    "чий це checkin" через підпис іншого власника не можна.
    """
    other_seed = b"\x77" * 32
    other_sk = nacl.signing.SigningKey(other_seed)
    ts = int(time.time())
    msg = canonical_json({
        "morok_dms_checkin": "v1",
        "pubkey": other_sk.verify_key.encode().hex(),
        "timestamp": ts,
    })
    forged_sig = ed25519_sign(msg, bytes(other_sk._seed)).hex()

    await _ensure_user(db)
    with pytest.raises(HTTPException) as e:
        await check_in_signed(
            SignedCheckInRequest(timestamp=ts, signature_hex=forged_sig),
            _session(), db, redis,  # сесія — OWNER, підпис — від "other"
        )
    assert e.value.status_code == 401


async def test_stale_timestamp_rejected(db, redis):
    await _ensure_user(db)
    old_ts = int(time.time()) - 400
    with pytest.raises(HTTPException) as e:
        await check_in_signed(
            SignedCheckInRequest(timestamp=old_ts, signature_hex=_sign_checkin(old_ts)),
            _session(), db, redis,
        )
    assert e.value.status_code == 401
    assert e.value.detail == "stale_timestamp"


async def test_future_timestamp_rejected(db, redis):
    """Вікно симетричне — занадто майбутній ts теж підозрілий."""
    await _ensure_user(db)
    future_ts = int(time.time()) + 400
    with pytest.raises(HTTPException) as e:
        await check_in_signed(
            SignedCheckInRequest(
                timestamp=future_ts, signature_hex=_sign_checkin(future_ts),
            ),
            _session(), db, redis,
        )
    assert e.value.status_code == 401


async def test_no_armed_dms_returns_zero_not_error(db, redis):
    """Немає жодного DMS — це не помилка, просто нічого бампати."""
    await _ensure_user(db)
    ts = int(time.time())
    result = await check_in_signed(
        SignedCheckInRequest(timestamp=ts, signature_hex=_sign_checkin(ts)),
        _session(), db, redis,
    )
    assert result.checked_in_count == 0


async def test_cancelled_dms_not_bumped(db, redis):
    """Тільки ARMED реагує на check-in — CANCELLED лишається як є."""
    await _ensure_user(db)
    from morok_relay.api.dms import cancel_dms
    info = await _armed_dms(db)
    await cancel_dms(info.dms_id, _session(), db, redis, proof=None)

    import uuid
    row = await db.get(DeadManSwitch, uuid.UUID(info.dms_id))
    frozen_checkin = row.last_check_in_at

    ts = int(time.time())
    await check_in_signed(
        SignedCheckInRequest(timestamp=ts, signature_hex=_sign_checkin(ts)),
        _session(), db, redis,
    )

    await db.refresh(row)
    assert row.last_check_in_at == frozen_checkin


# ── dms_checkin у MOROK_ACTION_PROOF_REQUIRED (персонально) ──
async def test_strict_mode_spares_owner_without_signed_client(db, redis, action_proof_required, fake_session):
    """Старий клієнт ніколи не робив підписаний check-in — для нього стара
    поведінка: bearer-check-in працює, bearer-активність теж «я живий»."""
    from morok_relay.api.dms import check_in
    from morok_relay.deps import get_current_session
    from morok_relay.sessions import create_session
    await _ensure_user(db)
    info = await _armed_dms(db)
    action_proof_required("dms_checkin")
    r = await check_in(info.dms_id, _session(), db, redis)
    assert r.dms_id == info.dms_id
    session = await create_session(redis, OWNER)
    await get_current_session(redis, authorization=f"Bearer {session.token}")
    assert await redis.exists(f"morok:dms:checkin_throttle:{OWNER}")


async def test_strict_mode_after_signed_checkin(db, redis, action_proof_required):
    """Клієнт уміє підписувати → bearer більше не підтверджує живість."""
    from morok_relay.api.dms import check_in
    from morok_relay.deps import get_current_session
    from morok_relay.sessions import create_session
    await _ensure_user(db)
    info = await _armed_dms(db)
    action_proof_required("dms_checkin")
    ts = int(time.time())
    r = await check_in_signed(
        SignedCheckInRequest(timestamp=ts, signature_hex=_sign_checkin(ts)),
        _session(), db, redis,
    )
    assert r.checked_in_count >= 1
    with pytest.raises(HTTPException) as e:
        await check_in(info.dms_id, _session(), db, redis)
    assert e.value.status_code == 410
    assert e.value.detail == "signed_checkin_required"
    await redis.delete(f"morok:dms:checkin_throttle:{OWNER}")
    session = await create_session(redis, OWNER)
    await get_current_session(redis, authorization=f"Bearer {session.token}")
    assert not await redis.exists(f"morok:dms:checkin_throttle:{OWNER}")


async def test_marker_ignored_when_strict_mode_off(db, redis, action_proof_required):
    from morok_relay.api.dms import check_in
    await _ensure_user(db)
    info = await _armed_dms(db)
    action_proof_required("account_delete")
    ts = int(time.time())
    await check_in_signed(
        SignedCheckInRequest(timestamp=ts, signature_hex=_sign_checkin(ts)),
        _session(), db, redis,
    )
    r = await check_in(info.dms_id, _session(), db, redis)
    assert r.dms_id == info.dms_id
