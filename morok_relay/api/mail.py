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
from ..deps import CurrentSession, DBSession, RedisClient
from ..mail_models import AliasStatus, MailAlias
from ..rate_limit import rate_limit_by_pubkey
from .. import blob_storage
from ..queue import enqueue_envelope

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
    pubkey: bytes = bytes.fromhex(session.pubkey_hex)
    want_primary = bool(body.get("primary", False))
    raw = body.get("alias")

    if want_primary:
        # PRIMARY = username акаунта (zalupa → zalupa@morok.email), не вводиться руками
        acc_username = (await db.execute(
            select(User.username).where(User.pubkey == pubkey))).scalar_one_or_none()
        if not acc_username:
            raise HTTPException(409, "Спершу займіть @username у месенджері — він стане вашою адресою")
        alias = acc_username.lower()
        if not _ALIAS_RE.fullmatch(alias):
            raise HTTPException(409, "Ваш username не підходить для email-адреси")
    elif raw is not None:
        alias = str(raw).strip().lower()
        if not _ALIAS_RE.fullmatch(alias) or ".." in alias:
            raise HTTPException(422, "Аліас: 3–64 символи, малі латинські, цифри, дефіс, крапка")
        if alias in RESERVED:
            raise HTTPException(409, "Цей аліас зарезервовано")
        # захист namespace: чужий username не можна взяти як аліас
        owner_of_name = (await db.execute(
            select(User.pubkey).where(User.username == alias))).scalar_one_or_none()
        if owner_of_name is not None and bytes(owner_of_name) != pubkey:
            raise HTTPException(409, "Це ім'я належить іншому користувачу в Morok")
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
    pubkey: bytes = bytes.fromhex(session.pubkey_hex)
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
    row = await _get_own_alias(db, bytes.fromhex(session.pubkey_hex), alias)
    if row.status == AliasStatus.DEAD:
        raise HTTPException(409, "Аліас уже вбито")
    row.status = AliasStatus.PAUSED
    await db.commit()
    return {"alias": row.alias, "status": "paused"}


@router.post("/aliases/{alias}/resume")
async def resume_alias(alias: str, session: CurrentSession, db: DBSession):
    row = await _get_own_alias(db, bytes.fromhex(session.pubkey_hex), alias)
    if row.status == AliasStatus.DEAD:
        raise HTTPException(409, "Мертвий аліас не відновлюється")
    row.status = AliasStatus.ACTIVE
    await db.commit()
    return {"alias": row.alias, "status": "active"}


@router.delete("/aliases/{alias}")
async def kill_alias(alias: str, session: CurrentSession, db: DBSession):
    row = await _get_own_alias(db, bytes.fromhex(session.pubkey_hex), alias)
    if row.is_primary:
        raise HTTPException(409, "Основну адресу не можна вбити")
    row.status = AliasStatus.DEAD
    await db.commit()
    return {"alias": row.alias, "status": "dead"}


# ────────────────────────────────────────────────────────────
# Фаза 2 — внутрішня пошта Morok↔Morok (E2EE, без SMTP)
# ────────────────────────────────────────────────────────────

@router.get("/resolve/{alias}")
async def resolve_alias(
    alias: str,
    session: CurrentSession,
    db: DBSession,
    _rl=Depends(rate_limit_by_pubkey("mail_resolve", limit_per_minute=30)),
):
    """
    Аліас → pubkey власника (щоб відправник міг зашифрувати лист для нього).
    Тільки active-аліаси. Потрібна авторизація (не публічний перелік).
    """
    a = alias.strip().lower()
    row = (await db.execute(
        select(MailAlias).where(MailAlias.alias == a))).scalar_one_or_none()
    if row is None or row.status != AliasStatus.ACTIVE:
        raise HTTPException(404, "Адресу не знайдено або вона не приймає пошту")
    return {"alias": a, "pubkey_hex": bytes(row.owner_pubkey).hex()}


@router.post("/send", status_code=status.HTTP_202_ACCEPTED)
async def send_internal(
    body: dict,
    session: CurrentSession,
    db: DBSession,
    redis: RedisClient,
    _rl=Depends(rate_limit_by_pubkey("mail_send", limit_per_minute=20)),
):
    """
    Внутрішній лист Morok→Morok. Клієнт уже зашифрував payload у формат
    morok-mail-v1 НА PUBKEY адресата (E2EE — сервер вміст не бачить).
    body: { "to_alias": "...", "blob_b64": "<base64 morok-mail-v1>" }
    Сервер лише резолвить аліас у чергу адресата й кладе конверт —
    так само, як робить SMTP-приймач для зовнішніх листів (channel="mail").
    Відправник на транспорті анонімний (from=""), особа — лише в шифрі.
    """
    import base64

    to_alias = str(body.get("to_alias", "")).strip().lower()
    blob_b64 = body.get("blob_b64")
    if not to_alias or not blob_b64:
        raise HTTPException(422, "to_alias і blob_b64 обовʼязкові")

    row = (await db.execute(
        select(MailAlias).where(MailAlias.alias == to_alias))).scalar_one_or_none()
    if row is None or row.status != AliasStatus.ACTIVE:
        raise HTTPException(404, "Адресу не знайдено або вона не приймає пошту")

    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except Exception:
        raise HTTPException(422, "blob_b64 не є валідним base64")
    s = get_settings()
    if len(blob) > s.mail_max_bytes:
        raise HTTPException(413, "Лист завеликий")

    envelope_id = secrets.token_hex(32)
    await blob_storage.write_blob(envelope_id, blob)
    ttl = s.mail_ttl_seconds
    expires = await enqueue_envelope(
        redis,
        envelope_id=envelope_id,
        sender_pubkey_hex="",
        recipient_pubkey_hex=bytes(row.owner_pubkey).hex(),
        timestamp=int(time.time()),
        ttl_seconds=ttl,
        signature_hex="",
        hard_ceiling_seconds=ttl,
        sealed=False,
        channel="mail",
    )
    # лічильник прийнятого — як у зовнішніх
    from sqlalchemy import update as _upd
    await db.execute(_upd(MailAlias).where(MailAlias.alias == to_alias)
                     .values(received_count=MailAlias.received_count + 1))
    await db.commit()
    if expires is None:
        return {"status": "duplicate"}

    try:
        from ..push_sender import trigger_push
        await trigger_push(db, redis, [bytes(row.owner_pubkey).hex()],
                           sender_username=None, kind="mail")
    except Exception as e:
        logger.warning("mail push (internal) failed: %s", e)

    logger.info("mail: internal send delivered")
    return {"status": "sent"}
