"""
morok.email — SMTP-приймач (окремий systemd-сервіс: morok-mail).

Запуск:  python -m morok_relay.mail_smtp
Порт:    25 (MOROK_MAIL_SMTP_PORT), біндиться як root або через CAP_NET_BIND_SERVICE.

Політика:
  RCPT → аліас шукається в БД:
      немає / dead → 550 (адреса не існує; reject на SMTP-етапі,
                      щоб не бути backscatter-джерелом)
      paused       → приймаємо 250 і ТИХО дропаємо (відправник не знає)
      active       → ок
  DATA → ліміт розміру (MOROK_MAIL_MAX_BYTES, дефолт 25 MB),
         SPF-перевірка (best-effort), конвертація → sealed конверт → черга.
  Rate limit: MOROK_MAIL_RL_PER_IP листів/хв з одного IP (дефолт 30).

Сервер НЕ зберігає: тіла листів (тільки RAM), логи вмісту, зв'язки.
Логи — тільки службові події без адрес (privacy-safe за замовчуванням).
"""
from __future__ import annotations

import asyncio
import logging
import time

import redis.asyncio as redis_async
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope as SMTPEnvelope
from aiosmtpd.smtp import Session as SMTPSession
from sqlalchemy import select, update

from .config import get_settings
from .db import get_sessionmaker
from .mail_convert import deliver_email
from .mail_models import AliasStatus, MailAlias

logger = logging.getLogger("morok.mail")

# ── SPF: best-effort, якщо бібліотека є ─────────────────────────────
try:
    import spf  # pyspf

    def _check_spf(ip: str, mail_from: str, helo: str) -> str:
        try:
            result, _ = spf.check2(i=ip, s=mail_from or "", h=helo or "")
            return result  # pass / fail / softfail / neutral / none / ...
        except Exception:
            return "none"
except ImportError:  # pyspf не встановлено — працюємо без SPF
    def _check_spf(ip: str, mail_from: str, helo: str) -> str:
        return "none"


class MorokMailHandler:
    def __init__(self):
        self.settings = get_settings()
        self.sessionmaker = get_sessionmaker()
        self.redis = redis_async.from_url(
            self.settings.redis_url, decode_responses=False
        )
        self.domain = getattr(self.settings, "mail_domain", "morok.email").lower()
        self.max_bytes = getattr(self.settings, "mail_max_bytes", 25 * 1024 * 1024)
        self.rl_per_ip = getattr(self.settings, "mail_rl_per_ip", 30)

    # ── IP rate limit (Redis, вікно 60 с) ────────────────────────────
    async def _ip_allowed(self, ip: str) -> bool:
        key = f"morok:mail_rl:{ip}"
        n = await self.redis.incr(key)
        if n == 1:
            await self.redis.expire(key, 60)
        return n <= self.rl_per_ip

    # ── RCPT ─────────────────────────────────────────────────────────
    async def handle_RCPT(
        self, server, session: SMTPSession, envelope: SMTPEnvelope,
        address: str, rcpt_options,
    ):
        addr = address.lower().strip()
        if "@" not in addr:
            return "550 5.1.3 Bad address"
        local, _, dom = addr.partition("@")
        if dom != self.domain:
            return "550 5.7.1 Relaying denied"

        ip = session.peer[0] if session.peer else "?"
        if not await self._ip_allowed(ip):
            return "450 4.7.1 Rate limit, try later"

        # службові адреси → маршрутизуються на admin-pubkey
        admin_hex = getattr(self.settings, "mail_admin_pubkey_hex", "")
        if local in ("postmaster", "abuse") and admin_hex:
            envelope.rcpt_tos.append(addr)
            session.morok_routes = getattr(session, "morok_routes", {})
            session.morok_routes[addr] = ("system", bytes.fromhex(admin_hex))
            return "250 OK"

        async with self.sessionmaker() as db:
            row = (
                await db.execute(select(MailAlias).where(MailAlias.alias == local))
            ).scalar_one_or_none()

        if row is None or row.status == AliasStatus.DEAD:
            return "550 5.1.1 No such user"

        envelope.rcpt_tos.append(addr)
        session.morok_routes = getattr(session, "morok_routes", {})
        session.morok_routes[addr] = (row.status.value, bytes(row.owner_pubkey))
        return "250 OK"

    # ── DATA ─────────────────────────────────────────────────────────
    async def handle_DATA(
        self, server, session: SMTPSession, envelope: SMTPEnvelope
    ):
        raw = envelope.original_content or envelope.content or b""
        if len(raw) > self.max_bytes:
            return "552 5.3.4 Message too big"

        ip = session.peer[0] if session.peer else "?"
        spf_result = _check_spf(ip, envelope.mail_from or "", session.host_name or "")

        routes = getattr(session, "morok_routes", {})
        delivered = 0
        for rcpt in envelope.rcpt_tos:
            status_val, owner_pubkey = routes.get(rcpt, (None, None))
            if owner_pubkey is None:
                continue
            if status_val == "paused":
                # тихий дроп: відправнику 250, лист у нікуди
                continue
            local = rcpt.split("@", 1)[0]
            try:
                await deliver_email(
                    self.redis, raw, local, owner_pubkey, spf_result
                )
                delivered += 1
                if status_val == "active":
                    async with self.sessionmaker() as db:
                        await db.execute(
                            update(MailAlias)
                            .where(MailAlias.alias == local)
                            .values(received_count=MailAlias.received_count + 1)
                        )
                        await db.commit()
            except Exception:
                logger.exception("mail: conversion failed")
                return "451 4.3.0 Temporary processing error"

        logger.info("mail: DATA ok, delivered=%d", delivered)
        return "250 OK"


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    settings = get_settings()
    port = getattr(settings, "mail_smtp_port", 25)
    handler = MorokMailHandler()
    controller = Controller(
        handler,
        hostname="0.0.0.0",
        port=port,
        ident="morok.email ESMTP",
    )
    controller.start()
    logger.info("morok-mail SMTP listening on :%s", port)
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        controller.stop()


if __name__ == "__main__":
    main()
