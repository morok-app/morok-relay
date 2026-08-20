"""
Account management endpoints.

Currently a single endpoint: DELETE /api/v1/me — permanent account
removal triggered by the authenticated user.

Authentication note: the caller already has a valid session token
(which proves they have the seed). The frontend additionally requires
the user to type their 24-word mnemonic before calling this endpoint,
as a second confirmation step against device theft. That check is
intentionally client-side — the relay never sees the mnemonic.
"""
from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter, Body, HTTPException, status
from sqlalchemy import delete, select

from ..config import get_settings
from ..deps import CurrentSession, DBSession, RedisClient
from ..schemas import SensitiveActionProof
from ..sensitive_action import verify_sensitive_action
from ..sessions import revoke_all_sessions
from ..models import (
    DeadManSwitch,
    EncryptedBackup,
    LoginLog,
    PushSubscription,
    User,
    UsernameHistory,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["account"])


@router.delete(
    "/me",
    summary="Permanently delete the authenticated user's account",
)
async def delete_me(
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
    proof: SensitiveActionProof | None = Body(default=None),
) -> dict:
    """
    Soft-delete the calling user and wipe their server-side data.

    What we do:
      - users.deleted_at = now()
      - Release the username (cooldown applies; recorded in username_history)
      - Delete push subscriptions for this pubkey
      - Delete encrypted seed backup (if any)
      - Delete dead-man's switches owned by this pubkey (recipients
        cascade via FK)
      - Redis: remove the inbox queue and the ws-active counter

    What we DO NOT do:
      - Touch group_members rows. If the user was an admin or member of
        a group, that group continues to function; their pubkey just
        becomes a tombstone ("@anon" in the UI). Doing otherwise would
        require either transferring admin ownership or destroying the
        group, both of which silently affect third parties.
      - Touch federation_outbound_queue rows. Envelopes already in
        flight finish delivering — they don't reveal anything about the
        user (the relay never had plaintext).
      - Touch username_history. The cooldown row IS created here, but
        we keep all historical entries so the cooldown rule keeps
        working across this deletion.

    Idempotent: a second call is a no-op (everything is already gone).
    """
    # Крипто-підтвердження (аудит зовн. №5, P1) — найважливіше
    # застосування sensitive_action.py: раніше вкрадений bearer сам
    # по собі був достатнім, щоб стерти акаунт, backup, DMS і історію
    # входів. Якщо клієнт передав підпис — перевіряємо fail-closed
    # ПЕРЕД будь-якою мутацією. Якщо ні — legacy bearer-only шлях,
    # без змін, поки клієнти не підтримають підписування.
    if proof is not None and proof.action_signature_hex is not None:
        settings = get_settings()
        valid = await verify_sensitive_action(
            redis,
            action="account_delete",
            pubkey_hex=current.pubkey_hex,
            target=current.pubkey_hex,
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

    pubkey_bytes = bytes.fromhex(current.pubkey_hex)
    now = int(time.time())

    # Load the user row
    stmt = select(User).where(User.pubkey == pubkey_bytes)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if user is None:
        # Nothing on this relay — still try to clean Redis below.
        pass
    else:
        # Release username with a cooldown entry, so it can't be
        # immediately grabbed by someone else.
        if user.username is not None:
            db.add(UsernameHistory(
                username=user.username,
                pubkey=pubkey_bytes,
                claimed_at=user.created_at,
                released_at=now,
            ))
            user.username = None
            # ВИПРАВЛЕНО (жорсткий прохід — знайдено самим собою, не
            # аудитом): username_changed_at МУСИТЬ скинутись разом із
            # username. Інакше сценарій «видалив → одразу відновив
            # тим самим seed» (_reactivate_if_deleted в auth.py) лишав
            # порожній акаунт (username=None) із чужим "минулим життям"
            # у username_changed_at — і людина, що хоче встановити
            # ПЕРШЕ ім'я в щойно відновленому акаунті, безпідставно
            # впиралась у 24-годинний інтервал, розрахований проти
            # зовсім іншого claim'у з попереднього життя цього pubkey.
            # Не дірка безпеки — легітимний UX-глухий кут.
            user.username_changed_at = None

        if user.deleted_at is None:
            user.deleted_at = now

    # Drop all push subscriptions
    await db.execute(
        delete(PushSubscription).where(PushSubscription.pubkey == pubkey_bytes)
    )

    # Drop the encrypted-seed backup if present
    await db.execute(
        delete(EncryptedBackup).where(EncryptedBackup.pubkey == pubkey_bytes)
    )

    # Drop dead-man switches (recipients cascade via FK ondelete=CASCADE)
    await db.execute(
        delete(DeadManSwitch).where(DeadManSwitch.creator_pubkey == pubkey_bytes)
    )

    # Журнал входів (аудит зовн. №2): «permanently delete» лишав у БД
    # login-рядки з pubkey, ip_hash і user-agent — при тому, що окремий
    # ендпоінт /me/sessions їх чистити ВМІЄ. Людина, що видаляє акаунт,
    # очікує саме зникнення слідів.
    await db.execute(
        delete(LoginLog).where(LoginLog.pubkey == pubkey_bytes)
    )

    await db.flush()

    # Redis cleanup — inbox queue and ws-active counter.
    # Wrapped because Redis errors should not roll the SQL transaction back.
    try:
        await redis.delete(f"morok:inbox:{current.pubkey_hex}")
        await redis.delete(f"morok:ws:active:{current.pubkey_hex}")
    except Exception as e:
        logger.warning("Redis cleanup on account delete failed: %s", e)

    # Знищуємо всі сесії й рвемо живі WebSocket'и.
    #
    # Без цього видалення акаунта лишало користувача… авторизованим:
    # валідність сесії визначається виключно токеном у Redis, а
    # deleted_at у цій перевірці не бере участі. Тобто після «видалити
    # акаунт» будь-який раніше виданий токен (у тому числі вкрадений)
    # продовжував працювати до кінця свого 7-денного вікна, а відкритий
    # сокет — приймати ack.
    #
    # ВИПРАВЛЕНО (аудит зовн. №5, MEDIUM): раніше збій тут ловився
    # мовчки — сервер логував WARNING і однаково відповідав
    # {"deleted": true}, попри те, що старі bearer могли лишитись
    # живими. Правдива атомарність тут неможлива (Postgres і Redis —
    # окремі системи, справжнього двофазного коміту немає, а Redis-
    # cleanup вище теж поза SQL-транзакцією), тож чесний компроміс:
    # кілька спроб проти тимчасового блимка + ЯВНИЙ прапорець
    # sessions_revoked у відповіді замість мовчазної брехні. Клієнт
    # (чи сама людина) тоді знає, що варто повторити спробу.
    revoked_count = 0
    sessions_revoked = False
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            revoked_count = await revoke_all_sessions(redis, current.pubkey_hex)
            sessions_revoked = True
            break
        except Exception as e:
            last_err = e
            if attempt < 2:
                await asyncio.sleep(0.2 * (attempt + 1))

    if sessions_revoked:
        logger.info(
            "Account delete %s: revoked %d session(s)",
            current.pubkey_hex[:8], revoked_count,
        )
    else:
        # ERROR, не WARNING: акаунт стерто, а старі сесії — ні. Це має
        # бути видно в моніторингу, не загублено серед звичайних логів.
        logger.error(
            "Account delete %s: session revoke FAILED after retries, "
            "old bearer tokens may still be valid: %s",
            current.pubkey_hex[:8], last_err,
        )

    logger.info("Account deleted: pubkey=%s...", current.pubkey_hex[:8])
    return {"deleted": True, "sessions_revoked": sessions_revoked}


# ============================================================================
# LOGIN AUDIT LOG ENDPOINTS
# ============================================================================

@router.get(
    "/me/sessions",
    summary="Get the user's login history (audit log)",
)
async def get_sessions(
    current: CurrentSession,
    db: DBSession,
) -> dict:
    """
    Return up to 30 most-recent login events for the calling user.

    Each event includes:
      - created_at (unix seconds)
      - ip_hash (sha256 hex — daily-rotated, see auth.py for details)
      - user_agent (truncated to 255 chars; nullable)

    The IP is intentionally NOT included — we never store it. The hash
    lets the user spot "this device is the same as that earlier one
    today" or "this came from a different network than usual"; raw IPs
    would be a target for subpoena.
    """
    pubkey_bytes = bytes.fromhex(current.pubkey_hex)
    stmt = (
        select(LoginLog)
        .where(LoginLog.pubkey == pubkey_bytes)
        .order_by(LoginLog.created_at.desc())
        .limit(30)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return {
        "sessions": [
            {
                "created_at": r.created_at,
                "ip_hash": r.ip_hash,
                "user_agent": r.user_agent,
            }
            for r in rows
        ],
    }


@router.delete(
    "/me/sessions",
    summary="Clear the user's login history",
)
async def clear_sessions(
    current: CurrentSession,
    db: DBSession,
) -> dict:
    """
    Wipe every login_log row for the calling user.

    This is purely a privacy convenience — the rows weren't accessible
    to anyone else, but a user might want to "start fresh" after a
    sensitive event (new device, paranoia, whatever).
    """
    pubkey_bytes = bytes.fromhex(current.pubkey_hex)
    result = await db.execute(
        delete(LoginLog).where(LoginLog.pubkey == pubkey_bytes)
    )
    await db.flush()
    return {"cleared": result.rowcount or 0}
