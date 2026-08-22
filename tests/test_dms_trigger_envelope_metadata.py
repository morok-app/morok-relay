"""
DMS-тригер: підпис релею був неперевірюваний, а мітки не доходили до
клієнта (детальний аналіз relay, P1 — зламана релізна фіча).

ЗНАХІДКА 1 — ПІДПИС. dms_reaper підписував dict із ВОСЬМИ полів
(from/to/ts/ttl/blob + kind/dms_creator_pubkey/dms_id), а
crypto.verify_envelope_signature будує канонічний JSON рівно з П'ЯТИ
(SIGNED_FIELDS). Отже підпис релею над DMS-конвертом не міг пройти
стандартну перевірку НІКОЛИ — ні для metadata, яку бачить клієнт, ні
для «повного» конверта з усіма полями (верифікатор усе одно відкидає
зайві). Заповіт доставлявся з битим підписом.

ЗНАХІДКА 2 — МІТКИ. kind/dms_creator_pubkey/dms_id писались у
sidecar-ключ morok:dms:envelope:{envelope_id}, який НЕ читало жодне
місце кодової бази (перевірено grep'ом по всьому репо). Одержувач
бачив звичайний конверт від невідомого pubkey (релею) — без будь-якої
ознаки, що це спрацьований Dead Man's Switch і чий саме.

ЯК ДОВЕСТИ РЕГРЕСІЮ. Відкотити _build_and_deliver_envelope до
підписування восьмиполевого dict і запису sidecar-ключа:
test_relay_signature_verifies_with_standard_verifier падає на
'signature invalid', а test_client_visible_metadata_carries_dms_marks
падає на відсутньому meta["kind"].
"""
from __future__ import annotations

import base64
import time
import uuid

import nacl.signing
import pytest

from morok_relay import queue as q
from morok_relay.blob_storage import read_blob
from morok_relay.config import get_settings
from morok_relay.crypto import ed25519_verify, verify_envelope_signature
from morok_relay.models import DeadManSwitch, DMSStatus
from morok_relay.scripts import dms_reaper

pytestmark = pytest.mark.asyncio

CREATOR = "77" * 32
RECIPIENT = "aa" * 32
PAYLOAD = b"\x01" * 128


def _relay_keypair() -> tuple[bytes, str]:
    """Справжня пара. Тестовий conftest виставляє НЕузгоджені
    MOROK_RELAY_PRIVKEY_HEX/PUBKEY_HEX, тож для перевірки підпису
    потрібен власний узгоджений ключ."""
    priv = bytes.fromhex("3c" * 32)
    pub = bytes(nacl.signing.SigningKey(priv).verify_key)
    return priv, pub.hex()


def _dms() -> DeadManSwitch:
    now = int(time.time())
    return DeadManSwitch(
        id=uuid.uuid4(),
        creator_pubkey=bytes.fromhex(CREATOR),
        trigger_seconds=3600,
        last_check_in_at=now - 90000,
        payload_encrypted=PAYLOAD,
        status=DMSStatus.ARMED,
        created_at=now - 90000,
    )


async def _fire_one(redis, monkeypatch, tmp_path) -> tuple[str, dict, bytes, str]:
    """Доставляє один DMS-конверт і повертає (envelope_id, meta,
    relay_priv, relay_pubkey_hex) — meta саме в тому вигляді, у якому
    її бачить клієнт через inbox."""
    monkeypatch.setattr(get_settings(), "blob_dir", tmp_path)
    relay_priv, relay_pub_hex = _relay_keypair()
    dms = _dms()

    envelope_id = await dms_reaper._build_and_deliver_envelope(
        redis=redis,
        dms=dms,
        recipient_pubkey=bytes.fromhex(RECIPIENT),
        relay_priv=relay_priv,
        relay_pubkey_hex=relay_pub_hex,
    )

    inbox = await q.list_inbox(redis, RECIPIENT)
    assert len(inbox) == 1, "DMS-конверт не потрапив у чергу одержувача"
    return envelope_id, inbox[0], relay_priv, relay_pub_hex


# ── ГОЛОВНИЙ ТЕСТ: підпис проходить стандартну перевірку ─────────────────
async def test_relay_signature_verifies_with_standard_verifier(
    redis, monkeypatch, tmp_path,
):
    """
    Конверт, зібраний РІВНО з того, що клієнт отримує від релею
    (metadata + blob із диска), має проходити той самий
    verify_envelope_signature, що й будь-який інший конверт у системі.
    """
    envelope_id, meta, _, relay_pub_hex = await _fire_one(
        redis, monkeypatch, tmp_path,
    )

    blob = await read_blob(envelope_id)
    assert blob == PAYLOAD

    envelope = {
        "from": meta["from"],
        "to": meta["to"],
        "ts": meta["ts"],
        "ttl": meta["ttl"],
        "blob": base64.b64encode(blob).decode(),
        "sig": meta["sig"],
    }
    ok, err = verify_envelope_signature(envelope)
    assert ok, f"підпис релею над DMS-конвертом не перевіряється: {err}"
    assert meta["from"] == relay_pub_hex


# ── мітки доходять до клієнта в САМІЙ metadata ──────────────────────────
async def test_client_visible_metadata_carries_dms_marks(
    redis, monkeypatch, tmp_path,
):
    envelope_id, meta, _, _ = await _fire_one(redis, monkeypatch, tmp_path)

    assert meta.get("kind") == "dms_trigger"
    assert meta.get("dms_creator_pubkey") == CREATOR
    assert meta.get("dms_id"), "dms_id відсутній у metadata"
    assert meta.get("dms_attestation_sig"), "атестація відсутня в metadata"

    # Те саме через get_envelope_meta (шлях WS-нотифікації), не тільки
    # через list_inbox.
    direct = await q.get_envelope_meta(redis, envelope_id)
    assert direct["kind"] == "dms_trigger"


# ── доменна атестація перевіряється ключем релею ────────────────────────
async def test_dms_attestation_verifies_and_is_bound_to_this_envelope(
    redis, monkeypatch, tmp_path,
):
    envelope_id, meta, _, relay_pub_hex = await _fire_one(
        redis, monkeypatch, tmp_path,
    )

    message = dms_reaper.build_dms_attestation_message(
        envelope_id=envelope_id,
        recipient_pubkey_hex=meta["to"],
        timestamp=meta["ts"],
        dms_creator_pubkey_hex=meta["dms_creator_pubkey"],
        dms_id=meta["dms_id"],
    )
    assert ed25519_verify(
        message,
        bytes.fromhex(meta["dms_attestation_sig"]),
        bytes.fromhex(relay_pub_hex),
    ), "доменна атестація DMS не перевіряється ключем релею"

    # Прив'язка до конкретного конверта: та сама атестація, підставлена
    # під ІНШИЙ envelope_id, не проходить — переграти її не можна.
    other = dms_reaper.build_dms_attestation_message(
        envelope_id="ff" * 32,
        recipient_pubkey_hex=meta["to"],
        timestamp=meta["ts"],
        dms_creator_pubkey_hex=meta["dms_creator_pubkey"],
        dms_id=meta["dms_id"],
    )
    assert not ed25519_verify(
        other,
        bytes.fromhex(meta["dms_attestation_sig"]),
        bytes.fromhex(relay_pub_hex),
    )


# ── sidecar-ключа більше немає ──────────────────────────────────────────
async def test_no_orphan_sidecar_key_written(redis, monkeypatch, tmp_path):
    """morok:dms:envelope:{id} не читало жодне місце кодової бази —
    це був мертвий ключ, що дублював metadata. Він не має писатись."""
    envelope_id, _, _, _ = await _fire_one(redis, monkeypatch, tmp_path)
    assert not await redis.exists(f"morok:dms:envelope:{envelope_id}")


# ── extra_meta не може підмінити канонічні поля ─────────────────────────
async def test_extra_meta_cannot_override_reserved_keys(redis):
    """
    Захисний тест на нову ручку enqueue_envelope(extra_meta=...):
    службові поля релею НЕ мають права затерти from/to/ts/ttl/sig —
    інакше помилковий (чи зловмисний) виклик тихо підмінив би
    відправника в metadata конверта.
    """
    with pytest.raises(ValueError):
        await q.enqueue_envelope(
            redis=redis,
            envelope_id="ab" * 32,
            sender_pubkey_hex="11" * 32,
            recipient_pubkey_hex=RECIPIENT,
            timestamp=int(time.time()),
            ttl_seconds=3600,
            signature_hex="ff" * 64,
            hard_ceiling_seconds=86400,
            extra_meta={"from": "99" * 32},
        )
