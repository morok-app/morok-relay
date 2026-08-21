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
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text as sa_text

from ..config import get_settings
from ..deps import CurrentSession, DBSession, RedisClient
from ..mail_models import AliasStatus, MailAlias, MailOutbound, OutboundStatus
from ..rate_limit import rate_limit_by_pubkey
from ..queue import write_blob_then_enqueue

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

    label = str(body.get("label") or "").strip()[:64] or None
    row = MailAlias(alias=alias, owner_pubkey=pubkey, is_primary=want_primary,
                    label=label)
    db.add(row)
    try:
        await db.commit()
    except IntegrityError:
        # Те саме, що з @username: SELECT-потім-INSERT це check-then-act,
        # два паралельні запити на один аліас обидва бачать «вільно».
        # UNIQUE на mail_aliases.alias не дає дублів, але без цього
        # користувач отримував 500 замість 409.
        await db.rollback()
        raise HTTPException(409, "Адреса зайнята")
    s = get_settings()
    logger.info("mail: alias created (primary=%s)", want_primary)
    return {"alias": alias, "address": f"{alias}@{s.mail_domain}",
            "primary": want_primary, "label": label}


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
            "label": a.label,
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


@router.post("/aliases/{alias}/label")
async def set_alias_label(
    alias: str,
    body: dict,
    session: CurrentSession,
    db: DBSession,
):
    """Встановити/змінити/прибрати підпис аліаса (порожній = прибрати)."""
    pubkey: bytes = bytes.fromhex(session.pubkey_hex)
    row = await _get_own_alias(db, pubkey, alias)
    row.label = str(body.get("label") or "").strip()[:64] or None
    await db.commit()
    return {"alias": row.alias, "label": row.label}


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

    pubkey: bytes = bytes.fromhex(session.pubkey_hex)
    to_alias = str(body.get("to_alias", "")).strip().lower()
    blob_b64 = body.get("blob_b64")

    # ── ЗОВНІШНІЙ адресат (є @ і домен ≠ наш) → черга вихідних ──
    if "@" in to_alias:
        _local, _dom = to_alias.rsplit("@", 1)
        if _dom != get_settings().mail_domain:
            return await _queue_external(body, session, db, to_alias)
        to_alias = _local  # свій домен → далі як внутрішній
    # from_alias: необовʼязковий. Якщо вказаний — має належати відправнику
    # (анти-спуфінг). Порожній → анонімний відправник.
    from_alias_raw = body.get("from_alias")
    from_alias = str(from_alias_raw).strip().lower() if from_alias_raw else ""
    if not to_alias or not blob_b64:
        raise HTTPException(422, "to_alias і blob_b64 обовʼязкові")

    row = (await db.execute(
        select(MailAlias).where(MailAlias.alias == to_alias))).scalar_one_or_none()
    if row is None or row.status != AliasStatus.ACTIVE:
        raise HTTPException(404, "Адресу не знайдено або вона не приймає пошту")

    # Анти-спуфінг: якщо відправник назвав аліас «від» — перевіряємо, що він
    # реально його (активний, у власності сесії). Інакше можна прикинутись
    # будь-ким. Сервер бачить лише from_alias (поза шифром), не вміст листа.
    if from_alias:
        own = (await db.execute(select(MailAlias).where(
            MailAlias.alias == from_alias,
            MailAlias.owner_pubkey == pubkey,
            MailAlias.status == AliasStatus.ACTIVE,
        ))).scalar_one_or_none()
        if own is None:
            raise HTTPException(403, "Адреса «від» не належить вам або неактивна")

    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except Exception:
        raise HTTPException(422, "blob_b64 не є валідним base64")
    s = get_settings()
    if len(blob) > s.mail_max_bytes:
        raise HTTPException(413, "Лист завеликий")

    envelope_id = secrets.token_hex(32)
    ttl = s.mail_ttl_seconds
    expires = await write_blob_then_enqueue(
        envelope_id, blob,
        redis=redis,
        sender_pubkey_hex="",
        recipient_pubkey_hex=bytes(row.owner_pubkey).hex(),
        timestamp=int(time.time()),
        ttl_seconds=ttl,
        signature_hex="",
        hard_ceiling_seconds=ttl,
        sealed=False,
        channel="mail",
        mail_origin="internal",       # блоб будував КЛІЄНТ → особі з блоба не довіряємо
        mail_from=from_alias or None,  # перевірений відправник (порожньо = анонім)
    )
    # лічильник прийнятого — як у зовнішніх
    from sqlalchemy import update as _upd
    await db.execute(_upd(MailAlias).where(MailAlias.alias == to_alias)
                     .values(received_count=MailAlias.received_count + 1))
    await db.commit()
    if expires is None:
        return {"status": "duplicate"}

    from ..push_sender import schedule_push
    schedule_push(redis, [bytes(row.owner_pubkey).hex()],
                  sender_username=None, kind="mail")

    logger.info("mail: internal send delivered")
    return {"status": "sent"}


# ────────────────────────────────────────────────────────────
# Фаза 3 — зовнішня відправка (черга + воркер CX23)
# ────────────────────────────────────────────────────────────

import re as _re
_EXT_ADDR_RE = _re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


async def _queue_external(body: dict, session, db, to_addr: str):
    """
    Кладе зовнішній лист у чергу mail_outbound. НЕ E2E: сервер бачить
    вміст до моменту доставки, після — стирає (див. worker report).
    """
    pubkey: bytes = bytes.fromhex(session.pubkey_hex)
    s = get_settings()

    if not _EXT_ADDR_RE.fullmatch(to_addr) or len(to_addr) > 255:
        raise HTTPException(422, "Некоректна адреса отримувача")

    # від: обовʼязковий власний активний аліас (зовнішній світ вимагає from)
    from_alias = str(body.get("from_alias") or "").strip().lower()
    if not from_alias:
        raise HTTPException(422, "Для зовнішніх листів потрібна адреса «від»")
    own = (await db.execute(select(MailAlias).where(
        MailAlias.alias == from_alias,
        MailAlias.owner_pubkey == pubkey,
        MailAlias.status == AliasStatus.ACTIVE,
    ))).scalar_one_or_none()
    if own is None:
        raise HTTPException(403, "Адреса «від» не належить вам або неактивна")

    subject = str(body.get("subject") or "").strip()[:998]
    text = str(body.get("text") or "")
    if not text.strip():
        raise HTTPException(422, "Порожній лист")
    if len(text.encode()) > s.mail_max_bytes:
        raise HTTPException(413, "Лист завеликий")

    # вкладення: ≤5 шт, сумарно ≤6MB у base64 (~4.5MB сирих)
    atts = body.get("attachments") or []
    if not isinstance(atts, list) or len(atts) > 5:
        raise HTTPException(422, "Забагато вкладень (максимум 5)")
    total = 0
    clean_atts = []
    for a in atts:
        b64 = str(a.get("b64") or "")
        fn = str(a.get("filename") or "file")[:255]
        ct = str(a.get("content_type") or "application/octet-stream")[:100]
        total += len(b64)
        if total > 6 * 1024 * 1024:
            raise HTTPException(413, "Вкладення завеликі (сумарно до ~4.5MB)")
        clean_atts.append({"filename": fn, "content_type": ct, "b64": b64})

    now = int(time.time())
    # добовий ліміт на акаунт (анти-абуза).
    # pg_advisory_xact_lock серіалізує compose ОДНОГО акаунта: без нього
    # COUNT → INSERT це класичний check-then-act — два паралельні запити
    # обидва бачать 19 і обидва вставляють (21 при ліміті 20). Лок
    # тримається до кінця транзакції, різні акаунти не блокують одне одного.
    await db.execute(
        sa_text("SELECT pg_advisory_xact_lock(hashtext(:pk))"),
        {"pk": pubkey.hex() if isinstance(pubkey, (bytes, bytearray)) else str(pubkey)},
    )
    sent_today = (await db.execute(
        select(func.count()).select_from(MailOutbound).where(
            MailOutbound.owner_pubkey == pubkey,
            MailOutbound.created_at > now - 86400,
        ))).scalar_one()
    if sent_today >= s.mail_out_user_daily:
        raise HTTPException(429, "Добовий ліміт вихідних листів вичерпано")

    in_reply_to = str(body.get("in_reply_to") or "").strip()[:256] or None
    references_hdr = str(body.get("references") or "").strip()[:2048] or None

    import json as _json
    row = MailOutbound(
        owner_pubkey=pubkey, from_alias=from_alias, to_addr=to_addr,
        subject=subject or None, body_text=text,
        attachments_json=_json.dumps(clean_atts) if clean_atts else None,
        in_reply_to=in_reply_to, references_hdr=references_hdr,
        status=OutboundStatus.QUEUED, attempts=0,
        created_at=now, updated_at=now,
    )
    db.add(row)
    await db.commit()
    logger.info("mailout: queued external")
    return {"status": "queued", "ref": str(row.id)}


def _check_worker_token(x_mailout_token: str | None):
    s = get_settings()
    if not s.mail_out_token or x_mailout_token != s.mail_out_token:
        raise HTTPException(401, "bad worker token")


@router.post("/outbound/claim")
async def outbound_claim(
    body: dict,
    db: DBSession,
    x_mailout_token: str | None = Header(default=None),
):
    """CX23-воркер забирає пачку queued → sending. Auth: X-Mailout-Token."""
    _check_worker_token(x_mailout_token)
    limit = min(int(body.get("limit", 5)), 20)
    now = int(time.time())

    # протухлі queued (48h, CX23 лежав) → failed без вмісту
    # with_for_update(skip_locked): другий воркер не чекає і не бере
    # ті самі рядки.
    stale = (await db.execute(select(MailOutbound).where(
        MailOutbound.status == OutboundStatus.QUEUED,
        MailOutbound.created_at < now - 172800,
    ).with_for_update(skip_locked=True))).scalars().all()
    for r in stale:
        r.status = OutboundStatus.FAILED
        r.last_error = "expired in queue"
        r.body_text = None; r.subject = None; r.attachments_json = None
        r.updated_at = now

    # SELECT ... FOR UPDATE SKIP LOCKED — два воркери, що claim'лять
    # одночасно, отримують НЕПЕРЕТИННІ пачки. Раніше обидва читали ті
    # самі queued-рядки і лист ішов двічі (перехід у SENDING робився
    # python-кодом уже після SELECT, commit — ще пізніше).
    rows = (await db.execute(select(MailOutbound).where(
        MailOutbound.status == OutboundStatus.QUEUED,
    ).order_by(MailOutbound.created_at).limit(limit)
     .with_for_update(skip_locked=True))).scalars().all()
    out = []
    for r in rows:
        r.status = OutboundStatus.SENDING
        r.attempts += 1
        r.updated_at = now
        import json as _json
        out.append({
            "id": str(r.id),
            "from_addr": f"{r.from_alias}@{get_settings().mail_domain}",
            "to_addr": r.to_addr,
            "subject": r.subject or "",
            "text": r.body_text or "",
            "attachments": _json.loads(r.attachments_json) if r.attachments_json else [],
            "in_reply_to": r.in_reply_to or "",
            "references": r.references_hdr or "",
        })
    await db.commit()
    return {"jobs": out}


@router.post("/outbound/report")
async def outbound_report(
    body: dict,
    db: DBSession,
    x_mailout_token: str | None = Header(default=None),
):
    """Воркер звітує результат. Вміст листа СТИРАЄТЬСЯ в будь-якому разі."""
    _check_worker_token(x_mailout_token)
    job_id = str(body.get("id") or "")
    ok = bool(body.get("ok"))
    err = str(body.get("error") or "")[:500]
    retry = bool(body.get("retry"))  # тимчасова відмова → назад у чергу
    row = (await db.execute(select(MailOutbound).where(
        MailOutbound.id == uuid.UUID(job_id)))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "job not found")
    now = int(time.time())
    if ok:
        row.status = OutboundStatus.DELIVERED
        row.body_text = None; row.subject = None; row.attachments_json = None
    elif retry and row.attempts < 5:
        row.status = OutboundStatus.QUEUED          # спробуємо ще (вміст лишається)
        row.last_error = err
    else:
        row.status = OutboundStatus.FAILED
        row.last_error = err
        row.body_text = None; row.subject = None; row.attachments_json = None
    row.updated_at = now
    await db.commit()
    return {"ok": True}


@router.get("/outbound/status")
async def outbound_status(
    session: CurrentSession,
    db: DBSession,
    _rl=Depends(rate_limit_by_pubkey("mail_ostatus", limit_per_minute=30)),
):
    """Статуси МОЇХ останніх вихідних (для ✓/⏳/✗ у «Відправлених»)."""
    pubkey: bytes = bytes.fromhex(session.pubkey_hex)
    rows = (await db.execute(select(MailOutbound).where(
        MailOutbound.owner_pubkey == pubkey,
    ).order_by(MailOutbound.created_at.desc()).limit(50))).scalars().all()
    return {"items": [{
        "ref": str(r.id),
        "to": r.to_addr,
        "status": r.status.value,
        "error": r.last_error,
        "ts": r.created_at,
    } for r in rows]}
