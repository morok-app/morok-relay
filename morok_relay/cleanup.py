"""
Background cleanup task: delete anonymous (username IS NULL) users
that haven't been seen for 7 days.

Runs once per day. Idempotent — safe to run multiple times.

Triggered from main.py lifespan. Logs how many users were reaped
each run.

Cascade effects when a user is deleted:
- Their inbox in Redis (morok:inbox:{pubkey}) — naturally expires;
  envelopes addressed to deleted users will be dropped on next list_inbox.
- Their entries in group_members — explicitly cleared here.
- Sessions in Redis — naturally expire (sliding TTL ~7 days anyway).
- Their backup row in encrypted_backups — anonymous users typically don't
  have backups, but cleared here just in case.
- Their DMS rows — cleared here.
"""
from __future__ import annotations

import asyncio
import logging
import time

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import db as _db
from .mail_models import MailOutbound, OutboundStatus
from .models import (
    DeadManSwitch,
    EncryptedBackup,
    GroupMember,
    User,
)

logger = logging.getLogger(__name__)

# Cleanup config
ANON_INACTIVE_SECONDS = 7 * 86400        # 7 days
CLEANUP_INTERVAL_SECONDS = 24 * 3600     # run once per day
CLEANUP_INITIAL_DELAY_SECONDS = 60       # wait 1min after startup
ACCOUNT_MIN_AGE_SECONDS = 3600           # don't reap accounts < 1h old
# Приватність: скільки тримати ЗАВЕРШЕНІ рядки вихідної пошти
# (delivered/failed) перш ніж прибрати їх разом із метаданими маршруту.
OUTBOUND_META_RETENTION_SECONDS = 7 * 86400   # 7 days after final status


async def reap_anonymous_users(session: AsyncSession) -> int:
    """
    Delete users with username IS NULL and last_seen_at older than threshold.

    Returns the count deleted. Cascades to group_members, dms, backups.
    """
    now = int(time.time())
    threshold = now - ANON_INACTIVE_SECONDS

    stmt = (
        select(User)
        .where(User.username.is_(None))
        .where(User.deleted_at.is_(None))
        .where(User.created_at < now - ACCOUNT_MIN_AGE_SECONDS)
        .where(
            (User.last_seen_at.is_(None)) | (User.last_seen_at < threshold)
        )
    )

    result = await session.execute(stmt)
    candidates = result.scalars().all()

    if not candidates:
        return 0

    deleted_count = 0
    for user in candidates:
        try:
            await session.execute(
                delete(GroupMember).where(GroupMember.pubkey == user.pubkey)
            )
            await session.execute(
                delete(EncryptedBackup).where(EncryptedBackup.pubkey == user.pubkey)
            )
            await session.execute(
                delete(DeadManSwitch).where(DeadManSwitch.creator_pubkey == user.pubkey)
            )
            await session.delete(user)
            deleted_count += 1
        except Exception as e:
            logger.warning(
                "Failed to reap anonymous user %s: %s",
                user.pubkey.hex()[:16], e,
            )
            continue

    return deleted_count


async def reap_delivered_outbound(session: AsyncSession) -> int:
    """
    Прибрати ЗАВЕРШЕНІ рядки вихідної пошти (delivered/failed), чий
    фінальний статус старший за retention-вікно.

    Навіщо: після доставки ВМІСТ листа вже занулено
    (body_text/subject/attachments_json у outbound_report). Але сам рядок
    досі несе метадані маршруту — owner_pubkey, from_alias, to_addr,
    created_at — тобто «ця особа написала на цю адресу тоді-то». Для
    privacy-продукту цей соцграф не має лежати безстроково. Клієнт тримає
    власну копію «Відправлених» (з фінальним ✓/✗) у себе в IndexedDB, тож
    видалення серверного рядка НЕ впливає на те, що бачить користувач.

    Безпека: чіпаємо ТІЛЬКИ delivered/failed. queued та sending (у
    польоті) не видаляємо ніколи. Рахунок за updated_at (проставляється
    коли рядок дійшов фінального статусу), тож рядок живе повне
    retention-вікно ПІСЛЯ завершення — кожен пристрій встигає опитати
    статус.
    """
    now = int(time.time())
    threshold = now - OUTBOUND_META_RETENTION_SECONDS
    result = await session.execute(
        delete(MailOutbound).where(
            MailOutbound.status.in_(
                (OutboundStatus.DELIVERED, OutboundStatus.FAILED)
            ),
            MailOutbound.updated_at < threshold,
        )
    )
    return result.rowcount or 0


async def cleanup_task_loop():
    """
    Background coroutine that wakes once per day and runs cleanup.
    Started from main.py lifespan.
    """
    await asyncio.sleep(CLEANUP_INITIAL_DELAY_SECONDS)
    while True:
        try:
            if _db._session_factory is None:
                logger.warning("Cleanup: session factory not ready yet")
            else:
                async with _db._session_factory() as session:
                    try:
                        count = await reap_anonymous_users(session)
                        mail_count = await reap_delivered_outbound(session)
                        await session.commit()
                        if count > 0:
                            logger.info(
                                "Cleanup: reaped %d anonymous users", count,
                            )
                        if mail_count > 0:
                            logger.info(
                                "Cleanup: reaped %d finished outbound-mail rows",
                                mail_count,
                            )
                        if count == 0 and mail_count == 0:
                            logger.debug("Cleanup: nothing to reap")
                    except Exception:
                        await session.rollback()
                        raise
        except asyncio.CancelledError:
            logger.info("Cleanup task cancelled")
            raise
        except Exception as e:
            logger.exception("Cleanup task failed: %s", e)

        try:
            await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            logger.info("Cleanup task cancelled during sleep")
            raise
