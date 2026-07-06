"""
morok.email — конвертер: вхідний MIME-лист → зашифрований конверт у чергу.

Потік (усе в RAM, на диск плейнтекст не пишеться НІКОЛИ):
    RCPT: аліас перевірено (active) →
    DATA: MIME → payload dict → JSON → libsodium sealed box на
          X25519(owner Ed25519 pubkey) → blob_storage → enqueue_envelope
          (sealed=True, без sender-подпису — як анонімний burner-send).

Формат blob (клієнт розшифровує tweetnacl sealed box, потім JSON):
{
  "kind": "email",
  "v": 1,
  "to_alias": "wren-otter-042",
  "from": "Alice <alice@gmail.com>",
  "subject": "...",
  "date": "RFC2822 date header",
  "text": "...",                 # text/plain, або конвертований з html
  "html": "..." | null,          # обрізаний до ліміту, може бути null
  "attachments": [               # тільки якщо влазять у ліміт
     {"filename": "...", "content_type": "...", "b64": "..."}
  ],
  "spf": "pass|fail|none",
  "received_at": 1720000000
}
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

import nacl.bindings

from .blob_storage import write_blob
from .config import get_settings
from .crypto import x25519_pubkey_from_ed25519
from .queue import enqueue_envelope

logger = logging.getLogger(__name__)

MAX_TEXT_CHARS = 200_000          # текст листа
MAX_HTML_CHARS = 300_000          # html-версія
MAX_ATTACH_TOTAL = 8 * 1024 * 1024   # сумарно вкладення в blob (base64 роздує +33%)


def _seal_to_ed25519(ed_pubkey: bytes, plaintext: bytes) -> bytes:
    """libsodium sealed box (анонімний відправник) на X25519-ключ власника."""
    x_pub = x25519_pubkey_from_ed25519(ed_pubkey)
    return nacl.bindings.crypto_box_seal(plaintext, x_pub)


def _extract_bodies(msg: EmailMessage) -> tuple[str, str | None]:
    """Повертає (text, html|None). Якщо тільки html — text робиться грубим стрипом."""
    text_part = msg.get_body(preferencelist=("plain",))
    html_part = msg.get_body(preferencelist=("html",))
    text = text_part.get_content() if text_part else ""
    html = html_part.get_content() if html_part else None
    if not text and html:
        # грубий strip тегів — краще ніж порожньо; нормальний рендер зробить клієнт
        import re
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text).strip()
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
            logger.info("mail: attachments over limit, truncating list")
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
    """
    Перетворює сирий лист на sealed-конверт і кладе у чергу власника.
    Повертає envelope_id або None (dedup).
    Викликається зі SMTP-хендлера. Кидає ValueError на сміттєвому MIME.
    """
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
    }
    blob = _seal_to_ed25519(owner_pubkey, json.dumps(payload, ensure_ascii=False).encode())

    envelope_id = secrets.token_hex(16)
    await write_blob(envelope_id, blob)

    ttl = getattr(s, "mail_ttl_seconds", 7 * 86400)  # недоставлені: 7 діб
    expires = await enqueue_envelope(
        redis,
        envelope_id=envelope_id,
        sender_pubkey_hex="",            # sealed: відправник у blob
        recipient_pubkey_hex=owner_pubkey.hex(),
        timestamp=int(time.time()),
        ttl_seconds=ttl,
        signature_hex="",
        hard_ceiling_seconds=ttl,
        sealed=True,
    )
    if expires is None:
        logger.info("mail: dedup hit for envelope")
        return None
    logger.info("mail: delivered to alias queue (ttl=%ss)", ttl)
    return envelope_id
