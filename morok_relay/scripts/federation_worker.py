"""
Federation outbound worker.

Run periodically via systemd timer (every minute).

Picks pending rows from federation_outbound_queue whose next_attempt_at
has arrived, marks them in_flight, attempts remote_forward(), and either
marks succeeded or schedules the next retry with exponential backoff.

Backoff schedule by attempt count:
    1: 30s     2: 1m     3: 2m     4: 5m     5: 15m
    6: 30m    7: 1h    8: 2h    9: 4h   10: 8h
   11+: dead_letter

In-flight recovery: any row that's been in_flight for > 5 minutes is
considered a crashed worker and gets put back to pending. Worker is
designed to be safe to run multiple instances concurrently — but with
a 1-minute systemd timer that's not expected.

Usage:
    python -m morok_relay.scripts.federation_worker
"""
from __future__ import annotations

import asyncio
import logging
import sys
import time

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

# IMPORTANT: import the module, not the variable. init_db() rebinds
# _session_factory at module level — if we did `from ..db import
# _session_factory`, we'd have our own local copy that stays None forever.
from .. import db as db_module
from ..federation_client import remote_forward
from ..models import FedQueueStatus, FederationOutboundQueue

logger = logging.getLogger(__name__)

# How many rows to attempt per worker run.
BATCH_SIZE = 50

# Max attempts before dead_letter.
MAX_ATTEMPTS = 11

# Recover in_flight rows older than this many seconds (crashed worker).
IN_FLIGHT_TIMEOUT_SECONDS = 300

# Backoff: attempts → seconds until next try
BACKOFF_SCHEDULE = {
    1: 30,
    2: 60,
    3: 120,
    4: 300,
    5: 900,
    6: 1800,
    7: 3600,
    8: 7200,
    9: 14400,
    10: 28800,
}


def backoff_seconds(attempts: int) -> int:
    """Return seconds to wait before the next attempt, given current count."""
    if attempts in BACKOFF_SCHEDULE:
        return BACKOFF_SCHEDULE[attempts]
    return BACKOFF_SCHEDULE[max(BACKOFF_SCHEDULE.keys())]


async def recover_stuck_in_flight(db: AsyncSession) -> int:
    """
    Move in_flight rows back to pending if they're older than the timeout.
    Returns count of recovered rows.
    """
    cutoff = int(time.time()) - IN_FLIGHT_TIMEOUT_SECONDS
    stmt = (
        update(FederationOutboundQueue)
        .where(FederationOutboundQueue.status == FedQueueStatus.IN_FLIGHT)
        .where(FederationOutboundQueue.next_attempt_at < cutoff)
        .values(status=FedQueueStatus.PENDING)
    )
    result = await db.execute(stmt)
    await db.commit()
    return result.rowcount or 0


async def fetch_pending_batch(db: AsyncSession) -> list[FederationOutboundQueue]:
    """Get up to BATCH_SIZE pending rows that are ready to send."""
    now = int(time.time())
    stmt = (
        select(FederationOutboundQueue)
        .where(FederationOutboundQueue.status == FedQueueStatus.PENDING)
        .where(FederationOutboundQueue.next_attempt_at <= now)
        .order_by(FederationOutboundQueue.next_attempt_at)
        .limit(BATCH_SIZE)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def mark_in_flight(db: AsyncSession, row: FederationOutboundQueue) -> bool:
    """
    Atomically mark a row in_flight. Returns False if someone else got it
    (race with parallel worker — shouldn't happen with 1-minute timer but
    we play safe).
    """
    now = int(time.time())
    stmt = (
        update(FederationOutboundQueue)
        .where(FederationOutboundQueue.id == row.id)
        .where(FederationOutboundQueue.status == FedQueueStatus.PENDING)
        .values(status=FedQueueStatus.IN_FLIGHT, next_attempt_at=now)
    )
    result = await db.execute(stmt)
    await db.commit()
    return (result.rowcount or 0) > 0


async def mark_succeeded(db: AsyncSession, row: FederationOutboundQueue) -> None:
    now = int(time.time())
    stmt = (
        update(FederationOutboundQueue)
        .where(FederationOutboundQueue.id == row.id)
        .values(
            status=FedQueueStatus.SUCCEEDED,
            delivered_at=now,
            last_error=None,
        )
    )
    await db.execute(stmt)
    await db.commit()


async def mark_retry_or_dead(
    db: AsyncSession,
    row: FederationOutboundQueue,
    error: str,
) -> None:
    """Bump attempts, schedule retry or move to dead_letter."""
    new_attempts = row.attempts + 1
    now = int(time.time())

    if new_attempts >= MAX_ATTEMPTS:
        stmt = (
            update(FederationOutboundQueue)
            .where(FederationOutboundQueue.id == row.id)
            .values(
                status=FedQueueStatus.DEAD_LETTER,
                attempts=new_attempts,
                last_error=error[:500],
            )
        )
        await db.execute(stmt)
        await db.commit()
        logger.error(
            "Dead-lettered envelope %s to %s after %d attempts: %s",
            row.envelope_id, row.target_relay, new_attempts, error,
        )
    else:
        wait = backoff_seconds(new_attempts)
        next_at = now + wait
        stmt = (
            update(FederationOutboundQueue)
            .where(FederationOutboundQueue.id == row.id)
            .values(
                status=FedQueueStatus.PENDING,
                attempts=new_attempts,
                next_attempt_at=next_at,
                last_error=error[:500],
            )
        )
        await db.execute(stmt)
        await db.commit()
        logger.info(
            "Retrying envelope %s to %s in %ds (attempt %d/%d)",
            row.envelope_id, row.target_relay, wait, new_attempts, MAX_ATTEMPTS,
        )


async def process_row(db: AsyncSession, row: FederationOutboundQueue) -> None:
    """Attempt to forward one envelope. Update status accordingly."""
    if not await mark_in_flight(db, row):
        return

    try:
        result = await remote_forward(row.target_relay, row.envelope_data)
    except Exception as e:
        await mark_retry_or_dead(db, row, f"exception: {type(e).__name__}: {e}")
        return

    if result is None:
        await mark_retry_or_dead(db, row, "remote_forward_returned_none")
        return

    if not result.get("accepted"):
        reason = result.get("reason") or "remote_rejected"
        await mark_retry_or_dead(db, row, f"rejected: {reason}")
        return

    await mark_succeeded(db, row)
    logger.info(
        "Delivered envelope %s to %s",
        row.envelope_id, row.target_relay,
    )


async def run_once() -> dict:
    """One pass: recover stuck, fetch batch, process each. Returns stats."""
    if db_module._session_factory is None:
        await db_module.init_db()

    factory = db_module._session_factory
    if factory is None:
        raise RuntimeError("Database session factory not initialized")

    stats = {"recovered": 0, "processed": 0, "succeeded": 0, "failed": 0}

    async with factory() as db:
        stats["recovered"] = await recover_stuck_in_flight(db)
        batch = await fetch_pending_batch(db)

    for row in batch:
        stats["processed"] += 1
        async with factory() as db:
            try:
                await process_row(db, row)
                async with factory() as check_db:
                    refreshed = await check_db.get(
                        FederationOutboundQueue, row.id
                    )
                    if refreshed and refreshed.status == FedQueueStatus.SUCCEEDED:
                        stats["succeeded"] += 1
                    else:
                        stats["failed"] += 1
            except Exception as e:
                logger.exception(
                    "Unexpected error processing row %s: %s", row.id, e
                )
                stats["failed"] += 1

    return stats


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        stats = await run_once()
        logger.info(
            "Federation worker run: recovered=%d processed=%d succeeded=%d failed=%d",
            stats["recovered"], stats["processed"],
            stats["succeeded"], stats["failed"],
        )
        return 0
    except Exception as e:
        logger.exception("Federation worker crashed: %s", e)
        return 1
    finally:
        try:
            await db_module.close_db()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
