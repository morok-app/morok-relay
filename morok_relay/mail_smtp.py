"""
morok.email — SMTP-приймач (systemd: morok-mail). python -m morok_relay.mail_smtp
RCPT: немає/dead → 550; paused → 250 + тихий дроп; active → ок.
DATA: ліміт розміру, SPF best-effort, конвертація → sealed конверт → черга.
Логи — без адрес (privacy-safe).

Окремий процес: aiosmtpd крутить власний event loop у фоновому потоці.
asyncpg-движок і redis МУСЯТЬ створюватися на ЦЬОМУ loop, інакше
"attached to a different loop". Тому init — лениво, всередині async-хендлерів
(_ensure_init), а не в main().
"""
from __future__ import annotations

import asyncio
import logging

import redis.asyncio as redis_async
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope as SMTPEnvelope
from aiosmtpd.smtp import Session as SMTPSession
from sqlalchemy import select, update

from . import db as _db
from .config import get_settings
from .db import init_db
from .mail_convert import deliver_email
from .mail_models import AliasStatus, MailAlias

logger = logging.getLogger("morok.mail")

try:
    import spf  # pyspf, опційно

    def _check_spf(ip: str, mail_from: str, helo: str) -> str:
        try:
            result, _ = spf.check2(i=ip, s=mail_from or "", h=helo or "")
            return result
        except Exception:
            return "none"
except ImportError:
    def _check_spf(ip: str, mail_from: str, helo: str) -> str:
        return "none"


class MorokMailHandler:
    def __init__(self):
        self.settings = get_settings()
        self.redis = None  # лениво, на loop контролера
        self.domain = self.settings.mail_domain.lower()
        self.max_bytes = self.settings.mail_max_bytes
        self.rl_per_ip = self.settings.mail_rl_per_ip

    async def _ensure_init(self):
        # виконується на loop контролера (з async-хендлера) — тут і біндимо
        if _db._session_factory is None:
            await init_db()
        if self.redis is None:
            self.redis = redis_async.from_url(
                self.settings.redis_url, decode_responses=False
            )

    async def _ip_allowed(self, ip: str) -> bool:
        key = f"morok:mail_rl:{ip}"
        n = await self.redis.incr(key)
        if n == 1:
            await self.redis.expire(key, 60)
        return n <= self.rl_per_ip

    async def handle_RCPT(self, server, session: SMTPSession,
                          envelope: SMTPEnvelope, address: str, rcpt_options):
        await self._ensure_init()
        addr = address.lower().strip()
        if "@" not in addr:
            return "550 5.1.3 Bad address"
        local, _, dom = addr.partition("@")
        if dom != self.domain:
            return "550 5.7.1 Relaying denied"

        ip = session.peer[0] if session.peer else "?"
        if not await self._ip_allowed(ip):
            return "450 4.7.1 Rate limit, try later"

        admin_hex = self.settings.mail_admin_pubkey_hex
        if local in ("postmaster", "abuse") and admin_hex:
            envelope.rcpt_tos.append(addr)
            session.morok_routes = getattr(session, "morok_routes", {})
            session.morok_routes[addr] = ("system", bytes.fromhex(admin_hex))
            return "250 OK"

        async with _db._session_factory() as db:
            row = (await db.execute(
                select(MailAlias).where(MailAlias.alias == local))).scalar_one_or_none()

        if row is None or row.status == AliasStatus.DEAD:
            return "550 5.1.1 No such user"

        envelope.rcpt_tos.append(addr)
        session.morok_routes = getattr(session, "morok_routes", {})
        session.morok_routes[addr] = (row.status.value, bytes(row.owner_pubkey))
        return "250 OK"

    async def handle_DATA(self, server, session: SMTPSession, envelope: SMTPEnvelope):
        await self._ensure_init()
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
                continue  # тихий дроп
            local = rcpt.split("@", 1)[0]
            try:
                await deliver_email(self.redis, raw, local, owner_pubkey, spf_result)
                delivered += 1
                if status_val == "active":
                    async with _db._session_factory() as db:
                        await db.execute(
                            update(MailAlias).where(MailAlias.alias == local)
                            .values(received_count=MailAlias.received_count + 1))
                        await db.commit()
            except Exception:
                logger.exception("mail: conversion failed")
                return "451 4.3.0 Temporary processing error"

        logger.info("mail: DATA ok, delivered=%d", delivered)
        return "250 OK"


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    settings = get_settings()
    handler = MorokMailHandler()
    controller = Controller(handler, hostname="0.0.0.0",
                            port=settings.mail_smtp_port, ident="morok.email ESMTP")
    controller.start()
    logger.info("morok-mail SMTP listening on :%s", settings.mail_smtp_port)
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        controller.stop()


if __name__ == "__main__":
    main()
