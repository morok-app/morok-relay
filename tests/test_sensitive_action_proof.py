"""
SensitiveActionProof (аудит зовн. №5, P1) — крипто-підтвердження для
незворотних дій: account_delete, backup_replace, backup_delete,
dms_cancel.

Знахідка: bearer доводить лише "хтось колись пройшов auth", не
"власник ключа підтверджує САМЕ ЦЮ дію ЗАРАЗ". Вкрадений bearer сам по
собі був достатнім, щоб стерти акаунт чи backup. Фікс — опціональний
Ed25519-підпис над (action, relay, timestamp, nonce, target), той
самий підхід, що DMS signed check-in і read receipt: зворотно-
сумісний, старі клієнти проходять bearer-only шляхом без змін.
"""
from __future__ import annotations

import time
import uuid

import nacl.signing
import pytest
from fastapi import HTTPException

from morok_relay.crypto import canonical_json, ed25519_sign
from morok_relay.sensitive_action import verify_sensitive_action

pytestmark = pytest.mark.asyncio

_SEED = b"\x61" * 32
_SK = nacl.signing.SigningKey(_SEED)
OWNER = _SK.verify_key.encode().hex()
RELAY = "relay1.morok.app"


def _sign(action: str, target: str, nonce: str, ts: int) -> str:
    msg = canonical_json({
        "morok_sensitive_action": "v1",
        "action": action,
        "relay": RELAY,
        "timestamp": ts,
        "nonce": nonce,
        "target": target,
    })
    return ed25519_sign(msg, bytes(_SK._seed)).hex()


# ── verify_sensitive_action: чиста логіка ────────────────────────────────
async def test_valid_signature_accepted(redis):
    ts = int(time.time())
    sig = _sign("account_delete", OWNER, "nonce-1", ts)
    assert await verify_sensitive_action(
        redis, action="account_delete", pubkey_hex=OWNER, target=OWNER,
        nonce="nonce-1", timestamp=ts, signature_hex=sig, relay_name=RELAY,
    ) is True


async def test_forged_signature_rejected(redis):
    ts = int(time.time())
    assert await verify_sensitive_action(
        redis, action="account_delete", pubkey_hex=OWNER, target=OWNER,
        nonce="nonce-2", timestamp=ts, signature_hex="00" * 64,
        relay_name=RELAY,
    ) is False


async def test_signature_bound_to_action_type(redis):
    """Підпис на 'dms_cancel' не годиться для 'account_delete' — той
    самий nonce/timestamp, інша дія."""
    ts = int(time.time())
    sig = _sign("dms_cancel", OWNER, "nonce-3", ts)
    assert await verify_sensitive_action(
        redis, action="account_delete", pubkey_hex=OWNER, target=OWNER,
        nonce="nonce-3", timestamp=ts, signature_hex=sig, relay_name=RELAY,
    ) is False


async def test_signature_bound_to_target(redis):
    """
    ГОЛОВНИЙ ТЕСТ прив'язки до об'єкта дії. Підпис на скасування ОДНОГО
    dms_id не має годитись для ІНШОГО — інакше один валідний підпис
    "скасувати DMS X" міг би бути переграний для довільного DMS того
    самого власника.
    """
    ts = int(time.time())
    dms_a = str(uuid.uuid4())
    dms_b = str(uuid.uuid4())
    sig = _sign("dms_cancel", dms_a, "nonce-4", ts)
    assert await verify_sensitive_action(
        redis, action="dms_cancel", pubkey_hex=OWNER, target=dms_b,
        nonce="nonce-4", timestamp=ts, signature_hex=sig, relay_name=RELAY,
    ) is False


async def test_signature_bound_to_relay(redis):
    """Підпис, виданий для relay1, не годиться на relay2 — запобігає
    переграванню між федеративними інстансами."""
    ts = int(time.time())
    sig = _sign("account_delete", OWNER, "nonce-5", ts)
    assert await verify_sensitive_action(
        redis, action="account_delete", pubkey_hex=OWNER, target=OWNER,
        nonce="nonce-5", timestamp=ts, signature_hex=sig,
        relay_name="relay2.morok.app",
    ) is False


async def test_stale_timestamp_rejected(redis):
    old_ts = int(time.time()) - 400
    sig = _sign("account_delete", OWNER, "nonce-6", old_ts)
    assert await verify_sensitive_action(
        redis, action="account_delete", pubkey_hex=OWNER, target=OWNER,
        nonce="nonce-6", timestamp=old_ts, signature_hex=sig,
        relay_name=RELAY,
    ) is False


async def test_nonce_replay_rejected(redis):
    """ГОЛОВНИЙ ТЕСТ anti-replay. Той самий валідний підпис вдруге —
    відмова: інакше вкрадений (перехоплений) підпис можна пред'явити
    повторно в межах вікна свіжості."""
    ts = int(time.time())
    sig = _sign("account_delete", OWNER, "nonce-7", ts)
    kw = dict(
        redis=redis, action="account_delete", pubkey_hex=OWNER,
        target=OWNER, nonce="nonce-7", timestamp=ts, signature_hex=sig,
        relay_name=RELAY,
    )
    assert await verify_sensitive_action(**kw) is True
    assert await verify_sensitive_action(**kw) is False


async def test_different_nonce_not_blocked_by_prior_replay_guard(redis):
    ts = int(time.time())
    sig1 = _sign("account_delete", OWNER, "nonce-8a", ts)
    sig2 = _sign("account_delete", OWNER, "nonce-8b", ts)
    assert await verify_sensitive_action(
        redis, action="account_delete", pubkey_hex=OWNER, target=OWNER,
        nonce="nonce-8a", timestamp=ts, signature_hex=sig1, relay_name=RELAY,
    ) is True
    assert await verify_sensitive_action(
        redis, action="account_delete", pubkey_hex=OWNER, target=OWNER,
        nonce="nonce-8b", timestamp=ts, signature_hex=sig2, relay_name=RELAY,
    ) is True


async def test_redis_failure_fails_closed_on_replay_layer(redis, monkeypatch):
    """
    ГОЛОВНИЙ ТЕСТ (жорсткий свіжий прохід — GPT-перегляд другого
    раунду). Fail-CLOSED на Redis-збій у anti-replay-шарі: для
    account_delete/backup_replace/backup_delete/dms_cancel
    correctness важливіша за availability. Крипто-валідний, але
    ПОВТОРЕНИЙ підпис не повинен проходити саме в момент деградації
    Redis — найгірший можливий час для тихої поступки безпеки.
    """
    ts = int(time.time())
    sig = _sign("account_delete", OWNER, "nonce-9", ts)

    async def boom(*a, **kw):
        raise ConnectionError("redis down")

    monkeypatch.setattr(redis, "set", boom)
    assert await verify_sensitive_action(
        redis, action="account_delete", pubkey_hex=OWNER, target=OWNER,
        nonce="nonce-9", timestamp=ts, signature_hex=sig, relay_name=RELAY,
    ) is False


async def test_delete_me_rejects_valid_proof_when_redis_replay_layer_down(
    db, redis, monkeypatch,
):
    """
    ГОЛОВНИЙ НАСКРІЗНИЙ ТЕСТ. Через реальний DELETE /me — навіть
    крипто-валідний підпис не проходить, якщо anti-replay-шар (Redis)
    недоступний саме в момент перевірки. Раніше це fail-open'ило б
    account_delete повз anti-replay захист.
    """
    from morok_relay.api.account import delete_me
    from morok_relay.config import get_settings
    from morok_relay.models import User, UserTier
    from morok_relay.schemas import SensitiveActionProof
    from morok_relay.sessions import Session

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(OWNER), username="frank",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()

    async def boom(*a, **kw):
        raise ConnectionError("redis down")
    monkeypatch.setattr(redis, "set", boom)

    session = Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)
    sig = _sign("account_delete", OWNER, "nonce-redis-down", now)
    proof = SensitiveActionProof(
        action_signature_hex=sig, action_nonce="nonce-redis-down",
        action_timestamp=now,
    )
    with pytest.raises(HTTPException) as e:
        await delete_me(session, db, redis, proof=proof)
    assert e.value.status_code == 401

    from sqlalchemy import select
    row = (await db.execute(
        select(User).where(User.pubkey == bytes.fromhex(OWNER))
    )).scalar_one()
    assert row.deleted_at is None, \
        "акаунт видалено попри недоступний anti-replay-шар"


# ── наскрізно: DELETE /me вимагає валідний proof, якщо переданий ────────
async def test_delete_me_rejects_forged_proof(db, redis):
    from morok_relay.api.account import delete_me
    from morok_relay.config import get_settings
    from morok_relay.models import User, UserTier
    from morok_relay.schemas import SensitiveActionProof
    from morok_relay.sessions import Session

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(OWNER), username="alice",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()

    session = Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)
    proof = SensitiveActionProof(
        action_signature_hex="00" * 64, action_nonce="x" * 10,
        action_timestamp=now,
    )
    with pytest.raises(HTTPException) as e:
        await delete_me(session, db, redis, proof=proof)
    assert e.value.status_code == 401
    assert e.value.detail == "invalid_action_proof"

    # акаунт не мав бути стертий — перевірка ДО будь-якої мутації
    from sqlalchemy import select
    row = (await db.execute(
        select(User).where(User.pubkey == bytes.fromhex(OWNER))
    )).scalar_one()
    assert row.deleted_at is None, "мутація сталась ДО перевірки proof"


async def test_delete_me_accepts_valid_proof(db, redis):
    from morok_relay.api.account import delete_me
    from morok_relay.config import get_settings
    from morok_relay.models import User, UserTier
    from morok_relay.schemas import SensitiveActionProof
    from morok_relay.sessions import Session

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(OWNER), username="bob",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()

    session = Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)
    sig = _sign("account_delete", OWNER, "nonce-del-1", now)
    proof = SensitiveActionProof(
        action_signature_hex=sig, action_nonce="nonce-del-1",
        action_timestamp=now,
    )
    result = await delete_me(session, db, redis, proof=proof)
    assert result == {"deleted": True, "sessions_revoked": True}


async def test_delete_me_still_works_without_proof_legacy(db, redis):
    """Контроль: клієнт БЕЗ підтримки підписування (жоден proof не
    переданий) досі працює bearer-only шляхом, без регресії."""
    from morok_relay.api.account import delete_me
    from morok_relay.config import get_settings
    from morok_relay.models import User, UserTier
    from morok_relay.sessions import Session

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(OWNER), username="carol",
                home_relay=settings.relay_name, tier=UserTier.FREE,
                created_at=now, last_seen_at=now))
    await db.commit()

    session = Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)
    result = await delete_me(session, db, redis, proof=None)
    assert result == {"deleted": True, "sessions_revoked": True}


# ── DMS cancel: target=dms_id, не self pubkey ────────────────────────────
async def test_dms_cancel_rejects_proof_for_different_dms(db, redis):
    import base64

    from morok_relay.api.dms import cancel_dms, create_dms
    from morok_relay.config import get_settings
    from morok_relay.models import User, UserTier
    from morok_relay.schemas import DMSCreate, SensitiveActionProof
    from morok_relay.sessions import Session

    settings = get_settings()
    now = int(time.time())
    db.add(User(pubkey=bytes.fromhex(OWNER), tier=UserTier.FREE,
                home_relay=settings.relay_name,
                created_at=now, last_seen_at=now))
    await db.commit()

    session = Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)
    info = await create_dms(
        DMSCreate(trigger_seconds=86400,
                  payload_encrypted=base64.b64encode(b"\x01" * 50).decode(),
                  recipient_pubkeys_hex=["aa" * 32], label=None),
        session, db,
    )

    wrong_target_sig = _sign("dms_cancel", str(uuid.uuid4()), "nonce-d1", now)
    proof = SensitiveActionProof(
        action_signature_hex=wrong_target_sig, action_nonce="nonce-d1",
        action_timestamp=now,
    )
    with pytest.raises(HTTPException) as e:
        await cancel_dms(info.dms_id, session, db, redis, proof=proof)
    assert e.value.status_code == 401
