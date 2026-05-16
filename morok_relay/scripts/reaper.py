"""
Blob and group reaper — secure-delete expired data.

Run manually:
    python -m morok_relay.scripts.reaper

Or via systemd timer (preferred — see deploy/morok-reaper.{service,timer}).

What it does
------------
1. Walk /var/lib/morok/blobs/ for every blob file. Delete if Redis no longer
   has the envelope (acked or queue-expired), or if older than hard ceiling.
2. Soft-delete groups whose expires_at has passed. The actual DB row is
   kept for 24h before hard deletion, so federated peers can stop trying
   to deliver. Member rows are cascade-deleted when the group is.

Secure-delete = overwrite with random bytes + unlink. On SSDs we rely on
periodic fstrim (separately scheduled) to actually erase the underlying
flash blocks.
"""
from __future__ import annotations

import asyncio
import logging
import sys
import time
from pathlib import Path

import redis.asyncio as redis_async
from sqlalchemy import select, update

from ..blob_storage import secure_delete_blob
from ..config import get_settings
from ..db import close_db, init_db
from ..models import Group


logger = logging.getLogger(__name__)


def _iter_blob_paths(blob_dir: Path):
    """Yield every blob file under blob_dir. Skips .tmp partial writes."""
    if not blob_dir.exists():
        return
    for path in blob_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix == ".tmp":
            continue
        name = path.name
        if len(name) != 64 or not all(c in "0123456789abcdef" for c in name):
            continue
        yield path


async def reap_blobs(redis: redis_async.Redis) -> dict:
    """One pass over the blob directory."""
    settings = get_settings()
    now = int(time.time())
    age_limit_seconds = settings.message_ttl_hard_seconds

    stats = {
        "blobs_scanned": 0,
        "blobs_still_queued": 0,
        "blobs_deleted_delivered": 0,
        "blobs_deleted_aged_out": 0,
        "blob_errors": 0,
    }

    for blob_path in _iter_blob_paths(settings.blob_dir):
        stats["blobs_scanned"] += 1
        envelope_id = blob_path.name

        try:
            blob_age = now - int(blob_path.stat().st_mtime)
            if blob_age > age_limit_seconds:
                deleted = await secure_delete_blob(envelope_id)
                if deleted:
                    stats["blobs_deleted_aged_out"] += 1
                    logger.info(
                        "Aged-out blob deleted: %s (age=%ds)",
                        envelope_id[:16], blob_age,
                    )
                continue

            exists = await redis.exists(f"morok:envelope:{envelope_id}")
            if exists:
                stats["blobs_still_queued"] += 1
                continue

            deleted = await secure_delete_blob(envelope_id)
            if deleted:
                stats["blobs_deleted_delivered"] += 1
        except Exception as e:
            stats["blob_errors"] += 1
            logger.exception("Reaper blob error on %s: %s", envelope_id[:16], e)

    return stats


async def reap_expired_groups() -> dict:
    """
    Soft-delete groups whose expires_at has passed.

    Soft-delete sets deleted_at; the database row remains for ~24h so
    that any in-flight delivery requests addressed to the group can
    return a meaningful 'group_deleted' instead of a generic 404.
    """
    from ..db import _session_factory
    if _session_factory is None:
        logger.error("DB not initialized for group reaper")
        return {"groups_expired": 0, "group_errors": 1}

    stats = {"groups_expired": 0, "group_errors": 0}
    now = int(time.time())

    async with _session_factory() as db:
        try:
            # Find expired but not yet soft-deleted groups
            stmt = select(Group).where(
                Group.expires_at.is_not(None),
                Group.expires_at <= now,
                Group.deleted_at.is_(None),
            )
            expired = (await db.execute(stmt)).scalars().all()

            if not expired:
                return stats

            for group in expired:
                logger.info(
                    "Expiring group %s (expires_at=%d, members=%d)",
                    str(group.id)[:8],
                    group.expires_at,
                    len(group.members) if group.members else 0,
                )

            # Bulk soft-delete in one statement
            stmt = (
                update(Group)
                .where(
                    Group.expires_at.is_not(None),
                    Group.expires_at <= now,
                    Group.deleted_at.is_(None),
                )
                .values(deleted_at=now)
            )
            result = await db.execute(stmt)
            await db.commit()
            stats["groups_expired"] = result.rowcount or 0
        except Exception as e:
            stats["group_errors"] += 1
            logger.exception("Group reaper error: %s", e)
            await db.rollback()

    return stats


async def reap_once() -> dict:
    """Run blob and group reaping in one pass."""
    settings = get_settings()
    start = time.monotonic()

    redis = redis_async.from_url(settings.redis_url, decode_responses=False)
    try:
        await redis.ping()
    except Exception as e:
        logger.error("Cannot connect to Redis: %s", e)
        await redis.aclose()
        return {"elapsed_seconds": time.monotonic() - start, "errors": 1}

    try:
        blob_stats = await reap_blobs(redis)
    finally:
        await redis.aclose()

    # Group reaper needs the DB session factory — initialize and tear down here.
    await init_db()
    try:
        group_stats = await reap_expired_groups()
    finally:
        await close_db()

    stats = {**blob_stats, **group_stats}
    stats["elapsed_seconds"] = time.monotonic() - start
    return stats


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )


async def _main() -> int:
    _setup_logging()
    logger.info("morok-reaper starting")
    stats = await reap_once()
    logger.info(
        "morok-reaper done: blobs scanned=%d queued=%d delivered=%d aged=%d "
        "groups_expired=%d errors=%d elapsed=%.2fs",
        stats.get("blobs_scanned", 0),
        stats.get("blobs_still_queued", 0),
        stats.get("blobs_deleted_delivered", 0),
        stats.get("blobs_deleted_aged_out", 0),
        stats.get("groups_expired", 0),
        stats.get("blob_errors", 0) + stats.get("group_errors", 0),
        stats.get("elapsed_seconds", 0.0),
    )
    total_errors = stats.get("blob_errors", 0) + stats.get("group_errors", 0)
    return 0 if total_errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
