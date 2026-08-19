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

import contextlib
import ipaddress
import logging
import os
import smtplib
import socket
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import dkim
import dns.resolver

logger = logging.getLogger("morok.mailout")


# ============================================================================
# MX SSRF guard (аудит зовн. №3, MEDIUM)
# ============================================================================
#
# ПРОБЛЕМА. Домен отримувача контролює його власник — це нормально для
# пошти (ми ЗОБОВ'ЯЗАНІ довіряти MX-запису, інакше лист нікуди не
# піде). Але без перевірки MX-hostname міг резолвитись у приватну/
# link-local адресу (10.x, 127.x, 169.254.169.254 — cloud metadata),
# і mail-out вузол зробив би вихідне TCP:25-з'єднання у ВНУТРІШНЮ
# мережу цього сервера. Другий шар — DNS rebinding: smtplib сам
# резолвить MX-hostname під час connect(), тобто НЕЗАЛЕЖНО від
# будь-якої попередньої перевірки — класичний check-then-use TOCTOU,
# той самий клас, що вже закритий у federation_client.py.
#
# ФІКС. Резолвимо MX ОДИН раз, перевіряємо ВСІ повернуті адреси як
# публічні, і тимчасово підміняємо socket.getaddrinfo так, щоб
# наступний connect() smtplib пішов рівно на перевірену IP — без
# другого resolve. host, переданий у smtplib.SMTP(), лишається ІМ'ЯМ
# MX (не IP) — SNI/сертифікат при STARTTLS перевіряються правильно.
#
# Безпечно монки-патчити ГЛОБАЛЬНИЙ socket.getaddrinfo: mailout_worker
# — однопотоковий послідовний цикл (claim → send_external → claim →
# ...), паралельних send_external немає, тож підміна в межах одного
# виклику нікому іншому не заважає.


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def _resolve_pinned_mx(hostname: str) -> str | None:
    """
    Резолвить MX-hostname, повертає ОДНУ публічну IPv4-адресу, або
    None якщо резолв не вдався чи хоч одна повернута адреса приватна.

    РЕГРЕСІЯ, ЗНАЙДЕНА В ПРОДІ (19.08): раніше тут не було family=,
    тобто getaddrinfo повертав і IPv4, і IPv6 разом. Weesь механізм
    egress на цьому вузлі жорстко прибитий до IPv4 (source_address=
    (SOURCE_IP, 0) нижче в send_external — навмисно, бо чистий PTR/
    репутація тут лише на IPv4). Якщо ips[0] випадково виявлявся IPv6
    (Gmail MX має AAAA-записи, і на хостах з IPv6-конективністю
    getaddrinfo часто повертає IPv6 першим) — pinned IP був IPv6, а
    source_address лишався IPv4: сокет AF_INET6 несумісний з IPv4-
    бінду, і smtplib падав з "Address family for hostname not
    supported" на КОЖНОМУ MX. Вхідна пошта це не зачіпало (інший
    код-шлях) — звідси симптом "приходить, не йде". Явний family=
    AF_INET прибирає цей клас неузгодженості раз і назавжди: pinned
    IP і source_address тепер гарантовано з однієї сім'ї.
    """
    try:
        infos = socket.getaddrinfo(
            hostname, 25, family=socket.AF_INET, proto=socket.IPPROTO_TCP,
        )
    except (socket.gaierror, UnicodeError, OSError):
        return None
    if not infos:
        return None
    ips = []
    for info in infos:
        ip_str = info[4][0]
        if not _is_public_ip(ip_str):
            return None  # хоч одна приватна — відмова повністю
        ips.append(ip_str)
    return ips[0]


@contextlib.contextmanager
def _pinned_dns(hostname: str, pinned_ip: str):
    """
    Тимчасово підміняє socket.getaddrinfo так, щоб САМЕ ЦЕЙ hostname
    резолвився лише в заздалегідь перевірену адресу — жодного другого
    (потенційно іншого) DNS resolve під час smtplib.connect().
    Інші hostname (яких тут бути не повинно, але про всяк випадок)
    ідуть через звичайний резолвер.
    """
    real_getaddrinfo = socket.getaddrinfo
    family = socket.AF_INET6 if ":" in pinned_ip else socket.AF_INET

    def _patched(host, port, *args, **kwargs):
        if host == hostname:
            return [(family, socket.SOCK_STREAM, 6, "", (pinned_ip, port))]
        return real_getaddrinfo(host, port, *args, **kwargs)

    socket.getaddrinfo = _patched
    try:
        yield
    finally:
        socket.getaddrinfo = real_getaddrinfo

# Конфіг вузла — з оточення, бо це деталі конкретної інсталяції, а не коду.
# SOURCE_IP порожній => egress не прибивається, ОС вибирає інтерфейс сама
# (для self-host це нормально; для нашого продакшену він заданий у .env,
# бо PTR і репутація живуть саме на тому IPv4).
DKIM_SELECTOR = os.environ.get("MOROK_MAIL_DKIM_SELECTOR", "s1").encode()
DKIM_DOMAIN = os.environ.get("MOROK_MAIL_DKIM_DOMAIN", "morok.email").encode()
DKIM_KEY_PATH = os.environ.get("MOROK_MAIL_DKIM_KEY_PATH", "/etc/morok/dkim/morok.private")
SOURCE_IP = os.environ.get("MOROK_MAIL_SOURCE_IP", "")
HELO_NAME = os.environ.get("MOROK_MAIL_HELO_NAME", "mail-out.morok.email")

# заголовки, що входять у DKIM-підпис (стабільні, присутні завжди)
DKIM_HEADERS = [b"From", b"To", b"Subject", b"Date", b"Message-ID", b"MIME-Version", b"Content-Type"]


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
        pinned_ip = _resolve_pinned_mx(mx)
        if pinned_ip is None:
            last_err = f"{mx}: resolves to non-public address or DNS failure"
            logger.warning(
                "mailout: MX %s rejected — private/unresolvable target", mx,
            )
            continue
        try:
            # source_address=(SOURCE_IP, 0) → egress прибитий до нашого IPv4.
            # Якщо MOROK_MAIL_SOURCE_IP не заданий — не прибиваємо взагалі
            # (передати ("", 0) у source_address = помилка bind).
            src = (SOURCE_IP, 0) if SOURCE_IP else None
            # host лишається ІМ'ЯМ mx (не pinned_ip) — SNI/сертифікат при
            # STARTTLS перевіряються за іменем; сам DNS-resolve усередині
            # connect() підмінений на перевірену адресу (_pinned_dns).
            with _pinned_dns(mx, pinned_ip):
                smtp = smtplib.SMTP(host=mx, port=25, local_hostname=HELO_NAME,
                                    timeout=30, source_address=src)
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
