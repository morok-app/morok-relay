"""
morok.email — керування аліасами.
POST /aliases | GET /aliases | POST /aliases/{a}/pause | /resume | DELETE /aliases/{a}
Прогрів: 1 primary + START одразу, +PER_MONTH/міс, стеля CAP.
"""
from __future__ import annotations

import logging
import re
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from ..config import get_settings
from ..deps import CurrentSession, DBSession
from ..mail_models import AliasStatus, MailAlias
from ..rate_limit import rate_limit_by_pubkey

logger = logging.getLogger(__name__)
router = APIRouter(tags=["mail"])

_ALIAS_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,62}[a-z0-9]$")
RESERVED = {
    "postmaster", "abuse", "admin", "administrator", "hostmaster",
    "webmaster", "root", "security", "noc", "support", "info",
    "no-reply", "noreply", "mailer-daemon", "help", "billing",
    "morok", "mail", "smtp", "mx",
}
_WORDS = ("amber ash aspen birch brook cedar cliff cloud coral crane dawn dune "
          "ember fern flint fog frost glade grove hazel heron iris ivy lark "
          "lichen lily lotus maple marsh mist moss oak onyx opal otter pine "
          "quail raven reef sable sage slate sparrow spruce stone swan thorn "
          "tide vale willow wren").split()


def _random_alias() -> str:
    return f"{secrets.choice(_WORDS)}-{secrets.choice(_WORDS)}-{secrets.randbelow(1000):03d}"


def alias_quota(account_created_at: int, now: int | None = None) -> int:
    s = get_settings()
    now = now or int(time.time())
    months = max(0, (now - account_created_at) // (30 * 86400))
    return min(s.mail_alias_cap, s.mail_alias_start + months * s.mail_alias_per_month)


@router.post("/aliases", status_code=status.HTTP_201_CREATED)
async def create_alias(
    body: dict,
    session: CurrentSession,
    db: DBSession,
    _rl=Depends(rate_limit_by_pubkey("mail_alias_create", limit_per_minute=5)),
):
    from ..models import User
    pubkey: bytes = session.pubkey
    want_primary = bool(body.get("primary", False))
    raw = body.get("alias")

    if raw is not None:
        alias = str(raw).strip().lower()
        if not _ALIAS_RE.fullmatch(alias) or ".." in alias:
            raise HTTPException(422, "Аліас: 3–64 символи, малі латинські, цифри, дефіс, крапка")
        if alias in RESERVED:
            raise HTTPException(409, "Цей аліас зарезервовано")
    else:
        alias = _random_alias()

    mine = (await db.execute(
        select(MailAlias).where(MailAlias.owner_pubkey == pubkey))).scalars().all()
    has_primary = any(a.is_primary and a.status != AliasStatus.DEAD for a in mine)
    non_primary_alive = sum(1 for a in mine if not a.is_primary and a.status != AliasStatus.DEAD)

    if want_primary and has_primary:
        raise HTTPException(409, "Основна адреса вже існує")

    if not want_primary:
        acc = (await db.execute(
            select(User.created_at).where(User.pubkey == pubkey))).scalar_one_or_none()
        if acc is None:
            raise HTTPException(403, "Акаунт не знайдено")
        quota = alias_quota(acc)
        if non_primary_alive >= quota:
            raise HTTPException(429, f"Ліміт аліасів: {quota}. Новий слот — з часом (+1/місяць) або з преміумом.")

    exists = (await db.execute(
        select(MailAlias.id).where(MailAlias.alias == alias))).scalar_one_or_none()
    if exists is not None:
        if raw is None:
            alias = _random_alias()
            exists = (await db.execute(
                select(MailAlias.id).where(MailAlias.alias == alias))).scalar_one_or_none()
        if exists is not None:
            raise HTTPException(409, "Адреса зайнята")

    row = MailAlias(alias=alias, owner_pubkey=pubkey, is_primary=want_primary)
    db.add(row)
    await db.commit()
    s = get_settings()
    logger.info("mail: alias created (primary=%s)", want_primary)
    return {"alias": alias, "address": f"{alias}@{s.mail_domain}", "primary": want_primary}


@router.get("/aliases")
async def list_aliases(session: CurrentSession, db: DBSession):
    from ..models import User
    pubkey: bytes = session.pubkey
    s = get_settings()
    rows = (await db.execute(
        select(MailAlias).where(MailAlias.owner_pubkey == pubkey)
        .order_by(MailAlias.is_primary.desc(), MailAlias.created_at))).scalars().all()
    acc = (await db.execute(
        select(User.created_at).where(User.pubkey == pubkey))).scalar_one_or_none()
    quota = alias_quota(acc) if acc else 0
    used = sum(1 for a in rows if not a.is_primary and a.status != AliasStatus.DEAD)
    return {
        "quota": quota, "used": used,
        "aliases": [{
            "alias": a.alias, "address": f"{a.alias}@{s.mail_domain}",
            "status": a.status.value, "primary": a.is_primary,
            "received": a.received_count, "created_at": a.created_at,
        } for a in rows],
    }


async def _get_own_alias(db, pubkey: bytes, alias: str) -> MailAlias:
    row = (await db.execute(
        select(MailAlias).where(MailAlias.alias == alias.lower(),
                                MailAlias.owner_pubkey == pubkey))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Аліас не знайдено")
    return row


@router.post("/aliases/{alias}/pause")
async def pause_alias(alias: str, session: CurrentSession, db: DBSession):
    row = await _get_own_alias(db, session.pubkey, alias)
    if row.status == AliasStatus.DEAD:
        raise HTTPException(409, "Аліас уже вбито")
    row.status = AliasStatus.PAUSED
    await db.commit()
    return {"alias": row.alias, "status": "paused"}


@router.post("/aliases/{alias}/resume")
async def resume_alias(alias: str, session: CurrentSession, db: DBSession):
    row = await _get_own_alias(db, session.pubkey, alias)
    if row.status == AliasStatus.DEAD:
        raise HTTPException(409, "Мертвий аліас не відновлюється")
    row.status = AliasStatus.ACTIVE
    await db.commit()
    return {"alias": row.alias, "status": "active"}


@router.delete("/aliases/{alias}")
async def kill_alias(alias: str, session: CurrentSession, db: DBSession):
    row = await _get_own_alias(db, session.pubkey, alias)
    if row.is_primary:
        raise HTTPException(409, "Основну адресу не можна вбити")
    row.status = AliasStatus.DEAD
    await db.commit()
    return {"alias": row.alias, "status": "dead"}
