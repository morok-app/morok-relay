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

import logging
import time

from fastapi import APIRouter
from sqlalchemy import delete, select

from ..deps import CurrentSession, DBSession, RedisClient
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
    try:
        revoked = await revoke_all_sessions(redis, current.pubkey_hex)
        logger.info(
            "Account delete %s: revoked %d session(s)",
            current.pubkey_hex[:8], revoked,
        )
    except Exception as e:
        logger.warning("Session revoke on account delete failed: %s", e)

    logger.info("Account deleted: pubkey=%s...", current.pubkey_hex[:8])
    return {"deleted": True}


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
