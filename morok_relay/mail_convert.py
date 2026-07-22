"""
morok.email — конвертер: вхідний MIME-лист → зашифрований конверт у чергу.

ФОРМАТ ШИФРУВАННЯ: morok-mail-v1 (доменно відокремлений від sealed-DM).
Збігається байт-у-байт із клієнтським crypto.mailOpen() — перевірено
крос-тестом Python(pynacl) ↔ JS(@noble), включно з емодзі/лапками/
керуючими символами у вмісті листа.

  eph X25519 keypair
  recip_x_pub = ed25519_pk_to_curve25519(owner_ed_pub)   # = edwardsToMontgomeryPub
  shared      = X25519(eph_priv, recip_x_pub)
  key         = HKDF-SHA256(ikm=shared, salt=eph_pub, info="morok-mail-v1", 32)
  ct          = XChaCha20-Poly1305-IETF(key, nonce24).encrypt(utf8(json))   # no AAD
  blob        = eph_pub(32) ‖ nonce(24) ‖ ct   → base64

Чому БЕЗ підпису-над-вмістом (на відміну від sealed-DM):
  тіло/тема листа контролює ЗОВНІШНІЙ відправник. Підпис над канонічним
  JSON вимагав би байт-ідентичної канонізації JS↔Python для будь-якого
  вмісту — крихко (спам із хитрим símволом ламав би розшифрування
  легітимного листа). JSON.parse на клієнті стійкий до будь-якого валідного
  JSON. Автентичність походження конверта забезпечується тим, що mail-конверт
  формує ТІЛЬКИ relay зі свого SMTP-приймача (див. mail_smtp), а не публічний
  API — тобто це та сама модель довіри, що й збірка inbox релеєм.

Потік: усе в RAM, плейнтекст на диск не пишеться НІКОЛИ.
"""
from __future__ import annotations

import base64
import json
import logging
import secrets
import time
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

import nacl.bindings as _sodium
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF

from .blob_storage import write_blob
from .config import get_settings
from .queue import enqueue_envelope

logger = logging.getLogger(__name__)

MAX_TEXT_CHARS = 200_000
MAX_HTML_CHARS = 300_000
MAX_ATTACH_TOTAL = 8 * 1024 * 1024

_MAIL_INFO = b"morok-mail-v1"


# ── крипта morok-mail-v1 ────────────────────────────────────────────
def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return _HKDF(algorithm=_hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def seal_mail(owner_ed_pubkey: bytes, payload: dict) -> bytes:
    """Запечатує payload для власника у форматі morok-mail-v1. Повертає blob."""
    eph_priv = _sodium.randombytes(32)
    eph_pub = _sodium.crypto_scalarmult_base(eph_priv)
    recip_x_pub = _sodium.crypto_sign_ed25519_pk_to_curve25519(owner_ed_pubkey)
    shared = _sodium.crypto_scalarmult(eph_priv, recip_x_pub)
    key = _hkdf_sha256(shared, eph_pub, _MAIL_INFO)
    nonce = _sodium.randombytes(24)
    pt = json.dumps(payload, ensure_ascii=False).encode()
    ct = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, b"", nonce, key)
    return eph_pub + nonce + ct


# ── MIME → payload ──────────────────────────────────────────────────
def _extract_bodies(msg: EmailMessage) -> tuple[str, str | None]:
    text_part = msg.get_body(preferencelist=("plain",))
    html_part = msg.get_body(preferencelist=("html",))
    text = text_part.get_content() if text_part else ""
    html = html_part.get_content() if html_part else None
    if not text and html:
        import re
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()
    return text[:MAX_TEXT_CHARS], (html[:MAX_HTML_CHARS] if html else None)


def _extract_attachments(msg: EmailMessage) -> list[dict]:
    out: list[dict] = []
    total = 0
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        if not payload:
            continue
        total += len(payload)
        if total > MAX_ATTACH_TOTAL:
            logger.info("mail: attachments over limit, truncating")
            break
        out.append({
            "filename": part.get_filename() or "attachment",
            "content_type": part.get_content_type(),
            "b64": base64.b64encode(payload).decode(),
        })
    return out


async def deliver_email(
    redis,
    raw_bytes: bytes,
    to_alias: str,
    owner_pubkey: bytes,
    spf_result: str,
) -> str | None:
    """Сирий лист → morok-mail-v1 конверт → черга власника. None = dedup."""
    s = get_settings()
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    text, html = _extract_bodies(msg)

    payload = {
        "kind": "email",
        "v": 1,
        "to_alias": to_alias,
        "from": str(msg.get("From", ""))[:512],
        "subject": str(msg.get("Subject", ""))[:998],
        "date": str(msg.get("Date", ""))[:64],
        "text": text,
        "html": html,
        "attachments": _extract_attachments(msg),
        "spf": spf_result,
        "received_at": int(time.time()),
        # для тредінгу відповідей (In-Reply-To/References у Gmail)
        "message_id": str(msg.get("Message-ID", "")).strip()[:256],
        "references": str(msg.get("References", "")).strip()[:2048],
    }
    blob = seal_mail(owner_pubkey, payload)

    envelope_id = secrets.token_hex(32)
    await write_blob(envelope_id, blob)

    ttl = getattr(s, "mail_ttl_seconds", 7 * 86400)
    expires = await enqueue_envelope(
        redis,
        envelope_id=envelope_id,
        sender_pubkey_hex="",
        recipient_pubkey_hex=owner_pubkey.hex(),
        timestamp=int(time.time()),
        ttl_seconds=ttl,
        signature_hex="",
        hard_ceiling_seconds=ttl,
        sealed=False,
        channel="mail",   # клієнт → crypto.mailOpen (не sealedDecrypt)
        mail_origin="external",  # блоб будував релей → блобу можна довіряти
    )
    if expires is None:
        logger.info("mail: dedup hit")
        return None
    logger.info("mail: delivered to alias queue (ttl=%ss)", ttl)
    return envelope_id
