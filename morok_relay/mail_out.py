"""
morok.email — вихідний відправник (Фаза 3). Крутиться на CX23 (mail-out).

Зовнішній лист НЕ E2E: отримувач — зовнішня пошта (Gmail тощо), тож сервер
бачить вміст, будує MIME, підписує DKIM і віддає на MX отримувача.
Внутрішня пошта Morok↔Morok лишається E2E — це інший шлях (api/mail.send).

Критично:
  - egress ПРИБИТИЙ до IPv4 SOURCE_IP (сервер за замовчуванням лізе в IPv6,
    а чистий PTR/репутація — саме на IPv4).
  - HELO/EHLO = HELO_NAME (=PTR), інакше -спам.
  - DKIM-підпис селектором s1, домен morok.email.
  - opportunistic STARTTLS (як більшість MX хоче).
"""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import dkim
import dns.resolver

logger = logging.getLogger("morok.mailout")

DKIM_SELECTOR = b"s1"
DKIM_DOMAIN = b"morok.email"
DKIM_KEY_PATH = "/etc/morok/dkim/morok.private"
SOURCE_IP = "77.42.19.151"
HELO_NAME = "mail-out.morok.email"

# заголовки, що входять у DKIM-підпис (стабільні, присутні завжди)
DKIM_HEADERS = [b"From", b"To", b"Subject", b"Date", b"Message-ID", b"MIME-Version"]


def build_message(from_addr: str, to_addr: str, subject: str, body_text: str,
                  body_html: str | None = None,
                  attachments: list[dict] | None = None,
                  in_reply_to: str | None = None,
                  references: str | None = None) -> EmailMessage:
    import base64 as _b64
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain="morok.email")
    # тредінг: Gmail/Proton клеять ланцюжок саме за цими заголовками
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = (f"{references} {in_reply_to}".strip() if references else in_reply_to)
    msg.set_content(body_text or "")
    if body_html:
        msg.add_alternative(body_html, subtype="html")
    for a in (attachments or []):
        try:
            data = _b64.b64decode(a.get("b64") or "")
            ct = a.get("content_type") or "application/octet-stream"
            maintype, _, subtype = ct.partition("/")
            msg.add_attachment(data, maintype=maintype or "application",
                               subtype=subtype or "octet-stream",
                               filename=a.get("filename") or "file")
        except Exception:
            logger.warning("mailout: skipping bad attachment")
    return msg


def dkim_sign(msg_bytes: bytes, key_path: str = DKIM_KEY_PATH) -> bytes:
    with open(key_path, "rb") as f:
        privkey = f.read()
    sig = dkim.sign(
        message=msg_bytes,
        selector=DKIM_SELECTOR,
        domain=DKIM_DOMAIN,
        privkey=privkey,
        include_headers=DKIM_HEADERS,
    )
    # dkim.sign повертає рядок "DKIM-Signature: ...\r\n" — додаємо на початок
    return sig + msg_bytes


def lookup_mx(domain: str) -> list[str]:
    answers = dns.resolver.resolve(domain, "MX")
    mxs = sorted((r.preference, str(r.exchange).rstrip(".")) for r in answers)
    return [host for _, host in mxs]


def send_external(from_addr: str, to_addr: str, subject: str,
                  body_text: str, body_html: str | None = None,
                  attachments: list[dict] | None = None,
                  in_reply_to: str | None = None,
                  references: str | None = None,
                  key_path: str = DKIM_KEY_PATH) -> tuple[bool, str]:
    """
    Надіслати зовнішній лист. Повертає (успіх, повідомлення).
    Пробує MX отримувача за пріоритетом. STARTTLS opportunistic.
    """
    try:
        domain = to_addr.split("@", 1)[1].lower()
    except IndexError:
        return False, "bad recipient address"

    try:
        mxs = lookup_mx(domain)
    except Exception as e:
        return False, f"MX lookup failed: {e}"
    if not mxs:
        return False, "no MX records"

    msg = build_message(from_addr, to_addr, subject, body_text, body_html,
                        attachments, in_reply_to, references)
    raw = dkim_sign(msg.as_bytes(), key_path)

    ctx = ssl.create_default_context()
    last_err = "unknown"
    for mx in mxs:
        try:
            # source_address=(SOURCE_IP, 0) → egress прибитий до нашого IPv4
            smtp = smtplib.SMTP(host=mx, port=25, local_hostname=HELO_NAME,
                                timeout=30, source_address=(SOURCE_IP, 0))
            try:
                smtp.ehlo(HELO_NAME)
                if smtp.has_extn("starttls"):
                    smtp.starttls(context=ctx)
                    smtp.ehlo(HELO_NAME)
                smtp.sendmail(from_addr, [to_addr], raw)
                smtp.quit()
                logger.info("mailout: delivered to %s via %s", domain, mx)
                return True, f"delivered via {mx}"
            finally:
                try:
                    smtp.close()
                except Exception:
                    pass
        except Exception as e:
            last_err = f"{mx}: {e}"
            logger.warning("mailout: MX %s failed: %s", mx, e)
            continue
    return False, f"all MX failed ({last_err})"


# ── CLI для тесту 3.4a: python3 -m morok_relay.mail_out FROM TO ──
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 3:
        print("usage: python3 -m morok_relay.mail_out <from@morok.email> <to@example.com>")
        sys.exit(1)
    frm, to = sys.argv[1], sys.argv[2]
    ok, info = send_external(
        frm, to,
        subject="Morok mail — тест доставки",
        body_text="Це тестовий лист із morok.email через власний відправник.\n\nЯкщо ти це читаєш — SPF/DKIM/DMARC працюють.",
    )
    print(("OK: " if ok else "FAIL: ") + info)
    sys.exit(0 if ok else 1)
