"""
Dead Man's Switch endpoints.

Rate limit: POST /api/v1/dms is limited to 5/min per pubkey because each
DMS row carries up to 256 KB payload — limiting creates prevents abuse.
GET/check-in/cancel are not limited (single-row reads or status flips).
"""
from __future__ import annotations

import base64
import time
import uuid

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy import text as sa_text
from sqlalchemy.orm import selectinload

from ..config import get_settings
from ..crypto import canonical_json, ed25519_verify
from ..deps import CurrentSession, DBSession, RedisClient
from ..models import DeadManSwitch, DMSRecipient, DMSStatus, User, UserTier
from ..rate_limit import rate_limit_by_pubkey
from ..sensitive_action import verify_sensitive_action
from ..schemas import (
    SensitiveActionProof,
    DMS_FREE_TIER_MAX_ACTIVE,
    DMS_FREE_TIER_MAX_RECIPIENTS,
    DMS_FREE_TIER_MAX_TOTAL_BYTES,
    DMS_PREMIUM_TIER_MAX_ACTIVE,
    DMS_PREMIUM_TIER_MAX_RECIPIENTS,
    DMS_PREMIUM_TIER_MAX_TOTAL_BYTES,
    DMSCancelResponse,
    DMSCheckInResponse,
    DMSCreate,
    DMSInfo,
    DMSRecipientInfo,
    SignedDMSCheckInResponse,
)

router = APIRouter(tags=["dms"])


async def _get_current_user(db, pubkey_hex: str) -> User:
    pubkey = bytes.fromhex(pubkey_hex)
    stmt = select(User).where(User.pubkey == pubkey)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if user is None:
        settings = get_settings()
        user = User(
            pubkey=pubkey,
            home_relay=settings.relay_name,
            tier=UserTier.FREE,
            last_seen_at=int(time.time()),
        )
        db.add(user)
        await db.flush()
    return user


def _parse_dms_id(dms_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(dms_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_dms_id",
        )


async def _load_dms_for_owner(
    db, dms_id: uuid.UUID, owner_pubkey: bytes, *, for_update: bool = False,
) -> DeadManSwitch:
    """
    for_update=True бере блокування рядка на час транзакції.

    Це критично для check-in і cancel. Без нього виходила гонка з
    dms_reaper: користувач читав рядок (SELECT не блокує), бачив
    status=ARMED, проходив перевірку — і лише потім, на записі, ставав у
    чергу за reaper'ом, який тим часом уже вирішив спрацювати й розіслав
    payload. Людина підтверджувала, що жива, а секрет уже пішов.

    Блокування має стояти з ОБОХ боків: reaper теж читає due-рядки через
    FOR UPDATE SKIP LOCKED. Тоді або користувач встиг перший (reaper
    пропускає цей DMS до наступного запуску і побачить свіжий
    last_check_in_at), або reaper перший (check-in чекає, а далі бачить
    уже не-ARMED статус і чесно віддає 409).

    Читання (list/get) блокування не беруть — їм воно не потрібне, і
    навпаки: зайві локи гальмували б reaper.
    """
    stmt = (
        select(DeadManSwitch)
        .where(DeadManSwitch.id == dms_id)
        .options(selectinload(DeadManSwitch.recipients))
    )
    if for_update:
        # of=DeadManSwitch — блокуємо лише сам DMS, не рядки recipients:
        # інакше FOR UPDATE зачепив би join'ені таблиці.
        stmt = stmt.with_for_update(of=DeadManSwitch)
    dms = (await db.execute(stmt)).scalar_one_or_none()
    if dms is None or dms.creator_pubkey != owner_pubkey:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="dms_not_found",
        )
    return dms


def _to_info(dms: DeadManSwitch) -> DMSInfo:
    return DMSInfo(
        dms_id=str(dms.id),
        trigger_seconds=dms.trigger_seconds,
        last_check_in_at=dms.last_check_in_at,
        fires_at=dms.last_check_in_at + dms.trigger_seconds,
        label=dms.label,
        status=dms.status.value,
        created_at=dms.created_at,
        triggered_at=dms.triggered_at,
        cancelled_at=dms.cancelled_at,
        recipients=[
            DMSRecipientInfo(
                recipient_pubkey_hex=r.recipient_pubkey.hex(),
                delivered_at=r.delivered_at,
            )
            for r in dms.recipients
        ],
    )


@router.post(
    "",
    response_model=DMSInfo,
    status_code=status.HTTP_201_CREATED,
    summary="Create a Dead Man's Switch",
    dependencies=[Depends(rate_limit_by_pubkey(
        "dms_create",
        get_settings().rate_limit_dms_create_per_minute,
    ))],
)
async def create_dms(
    body: DMSCreate,
    current: CurrentSession,
    db: DBSession,
) -> DMSInfo:
    user = await _get_current_user(db, current.pubkey_hex)
    if user.tier == UserTier.PREMIUM or user.tier == UserTier.ADMIN:
        max_recipients = DMS_PREMIUM_TIER_MAX_RECIPIENTS
        max_active = DMS_PREMIUM_TIER_MAX_ACTIVE
        max_bytes = DMS_PREMIUM_TIER_MAX_TOTAL_BYTES
    else:
        max_recipients = DMS_FREE_TIER_MAX_RECIPIENTS
        max_active = DMS_FREE_TIER_MAX_ACTIVE
        max_bytes = DMS_FREE_TIER_MAX_TOTAL_BYTES

    if len(body.recipient_pubkeys_hex) > max_recipients:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"too_many_recipients_for_tier_max_{max_recipients}",
        )

    creator_pubkey = bytes.fromhex(current.pubkey_hex)
    now = int(time.time())
    payload_bytes = base64.b64decode(body.payload_encrypted, validate=True)

    # Квота count+bytes на АКТИВНІ DMS (аудит зовн. №3, HIGH — DMS як
    # дешева машина забивання Postgres). rate_limit_dms_create обмежує
    # лише ЧАСТОТУ створення (5/хв) — при 256 KB на запис це ~1.76 GiB/
    # добу з ОДНОГО pubkey, а Ed25519-ідентичності дешеві, тож per-pubkey
    # rate-limit не є Sybil-перешкодою.
    #
    # ВИПРАВЛЕНО (аудит зовн. №5, MEDIUM): попередній коментар тут
    # стверджував, що гонка "в найгіршому разі дає ОДИН зайвий рядок"
    # — це неправда, той самий клас check-then-insert race, що ми вже
    # закривали для inbox depth і group capacity. N одночасних
    # create_dms можуть УСІ виконати SELECT до того, як хоч один
    # закомітить INSERT — усі бачать однаковий active_count, усі
    # проходять. pg_advisory_xact_lock (той самий підхід, що вже working
    # для mail-квоти в api/mail.py) серіалізує конкурентні create_dms
    # ЛИШЕ для ЦЬОГО pubkey — інші користувачі не блокуються. Лок
    # тримається до кінця транзакції запиту.
    await db.execute(
        sa_text("SELECT pg_advisory_xact_lock(hashtext(:pk))"),
        {"pk": current.pubkey_hex},
    )
    active_stmt = (
        select(func.count(), func.coalesce(func.sum(
            func.length(DeadManSwitch.payload_encrypted)
        ), 0))
        .where(
            DeadManSwitch.creator_pubkey == creator_pubkey,
            DeadManSwitch.status == DMSStatus.ARMED,
        )
    )
    active_count, active_bytes = (await db.execute(active_stmt)).one()
    if active_count >= max_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"too_many_active_dms_max_{max_active}",
        )
    if active_bytes + len(payload_bytes) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"dms_storage_quota_exceeded_max_{max_bytes}_bytes",
        )

    dms = DeadManSwitch(
        creator_pubkey=creator_pubkey,
        trigger_seconds=body.trigger_seconds,
        last_check_in_at=now,
        payload_encrypted=payload_bytes,
        label=body.label,
        status=DMSStatus.ARMED,
    )
    db.add(dms)
    await db.flush()

    for pk_hex in body.recipient_pubkeys_hex:
        db.add(DMSRecipient(
            dms_id=dms.id,
            recipient_pubkey=bytes.fromhex(pk_hex),
        ))
    await db.flush()
    await db.refresh(dms, attribute_names=["recipients"])
    return _to_info(dms)


@router.get("", response_model=list[DMSInfo])
async def list_my_dms(
    current: CurrentSession, db: DBSession,
) -> list[DMSInfo]:
    pubkey = bytes.fromhex(current.pubkey_hex)
    stmt = (
        select(DeadManSwitch)
        .where(DeadManSwitch.creator_pubkey == pubkey)
        .options(selectinload(DeadManSwitch.recipients))
        .order_by(DeadManSwitch.created_at.desc())
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_info(d) for d in rows]


@router.get("/{dms_id}", response_model=DMSInfo)
async def get_dms(
    dms_id: str, current: CurrentSession, db: DBSession,
) -> DMSInfo:
    did = _parse_dms_id(dms_id)
    pubkey = bytes.fromhex(current.pubkey_hex)
    dms = await _load_dms_for_owner(db, did, pubkey)
    return _to_info(dms)


class SignedCheckInRequest(BaseModel):
    """
    Підписаний proof-of-life (аудит зовн. №3, HIGH).

    ЧОМУ ЦЕ ІСНУЄ. `get_current_session` (deps.py) досі bump'ить
    last_check_in_at усіх ARMED DMS на БУДЬ-ЯКИЙ автентифікований
    запит — це залишається fallback'ом для клієнтів, які ще не вміють
    підписувати heartbeat. Але семантично це неправильно: bearer-
    токен доводить лише "хтось колись пройшов auth і отримав сесію",
    не "власник ключа живий ЗАРАЗ". Викрадений bearer (навіть у межах
    нашої 30-денної абсолютної стелі) міг придушувати DMS до місяця.

    Цей ендпоінт — правильний шлях: підпис Ed25519 із domain
    separation ("morok_dms_checkin:v1") і вузьким вікном свіжості,
    так само як access-контроль скрізь у федерації. Клієнт підписує
    сам, автономно, без запиту challenge — periodic background job,
    що раз на день ставить підпис на поточний timestamp.

    Коли клієнт (RN/web) навчиться викликати цей ендпоінт, generic
    bearer-bump можна буде прибрати або ще сильніше обмежити.
    """
    timestamp: int = Field(..., ge=0)
    signature_hex: str = Field(..., pattern=r"^[0-9a-f]{128}$")


@router.post(
    "/checkin-signed",
    response_model=SignedDMSCheckInResponse,
    summary="Cryptographic DMS proof-of-life (Ed25519-signed, not bearer-based)",
    dependencies=[Depends(rate_limit_by_pubkey(
        "dms_checkin_signed",
        get_settings().rate_limit_dms_create_per_minute,
    ))],
)
async def check_in_signed(
    body: SignedCheckInRequest,
    current: CurrentSession,
    db: DBSession,
) -> SignedDMSCheckInResponse:
    """
    current.pubkey_hex тут — вже верифікований bearer, тобто ЦЕЙ шлях
    ще не сильніший за bearer сам по собі (аутентифікація однакова).
    Реальна перевага прийде, коли клієнт зможе слати підпис БЕЗ живої
    сесії (наприклад, фоновий процес з локально збереженим ключем) —
    інфраструктура готова заздалегідь, підпис перевіряється незалежно
    від bearer-стану.
    """
    now = int(time.time())
    if abs(now - body.timestamp) > 300:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="stale_timestamp",
        )

    message = canonical_json({
        "morok_dms_checkin": "v1",
        "pubkey": current.pubkey_hex,
        "timestamp": body.timestamp,
    })
    pubkey_bytes = bytes.fromhex(current.pubkey_hex)
    try:
        sig_bytes = bytes.fromhex(body.signature_hex)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_signature",
        )
    if not ed25519_verify(message, sig_bytes, pubkey_bytes):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_signature",
        )

    bumped = await bump_check_in_for_pubkey(db, current.pubkey_hex)
    await db.commit()
    return SignedDMSCheckInResponse(
        checked_in_count=bumped,
        checked_in_at=now,
    )


@router.post("/{dms_id}/check-in", response_model=DMSCheckInResponse)
async def check_in(
    dms_id: str, current: CurrentSession, db: DBSession,
) -> DMSCheckInResponse:
    did = _parse_dms_id(dms_id)
    pubkey = bytes.fromhex(current.pubkey_hex)
    dms = await _load_dms_for_owner(db, did, pubkey, for_update=True)
    if dms.status != DMSStatus.ARMED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"dms_not_armed_status_{dms.status.value}",
        )
    now = int(time.time())
    dms.last_check_in_at = now
    await db.flush()
    return DMSCheckInResponse(
        dms_id=str(dms.id),
        last_check_in_at=now,
        fires_at=now + dms.trigger_seconds,
    )


@router.delete("/{dms_id}", response_model=DMSCancelResponse)
async def cancel_dms(
    dms_id: str, current: CurrentSession, db: DBSession, redis: RedisClient,
    proof: SensitiveActionProof | None = Body(default=None),
) -> DMSCancelResponse:
    did = _parse_dms_id(dms_id)
    pubkey = bytes.fromhex(current.pubkey_hex)
    dms = await _load_dms_for_owner(db, did, pubkey, for_update=True)
    if dms.status == DMSStatus.TRIGGERED:
        return DMSCancelResponse(dms_id=str(dms.id), cancelled=False)
    if dms.status == DMSStatus.CANCELLED:
        return DMSCancelResponse(dms_id=str(dms.id), cancelled=True)

    # Крипто-підтвердження (аудит зовн. №5, P1). target=dms_id (не self
    # pubkey!) — прив'язує підпис до КОНКРЕТНОГО DMS, інакше один
    # валідний підпис на "скасування" міг би переграно закрити ІНШИЙ
    # DMS того самого власника.
    if proof is not None and proof.action_signature_hex is not None:
        settings = get_settings()
        valid = await verify_sensitive_action(
            redis,
            action="dms_cancel",
            pubkey_hex=current.pubkey_hex,
            target=str(did),
            nonce=proof.action_nonce or "",
            timestamp=proof.action_timestamp or 0,
            signature_hex=proof.action_signature_hex,
            relay_name=settings.relay_name,
        )
        if not valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_action_proof",
            )

    dms.status = DMSStatus.CANCELLED
    dms.cancelled_at = int(time.time())
    # Scrub (аудит зовн. №3, HIGH): cancel лише ставив статус, ciphertext
    # лишався в БД назавжди — а це той самий payload, який людина щойно
    # explicitly відкликала. Порожні байти замість NULL: колонка
    # nullable=False лишається валідною безміграції.
    dms.payload_encrypted = b""
    await db.flush()
    return DMSCancelResponse(dms_id=str(dms.id), cancelled=True)


async def bump_check_in_for_pubkey(db, pubkey_hex: str) -> int:
    pubkey = bytes.fromhex(pubkey_hex)
    now = int(time.time())
    stmt = (
        update(DeadManSwitch)
        .where(
            DeadManSwitch.creator_pubkey == pubkey,
            DeadManSwitch.status == DMSStatus.ARMED,
        )
        .values(last_check_in_at=now)
    )
    result = await db.execute(stmt)
    return result.rowcount or 0
