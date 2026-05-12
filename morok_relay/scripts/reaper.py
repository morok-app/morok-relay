"""
Blob reaper — secure-delete expired or already-delivered blobs.

Run manually:
    python -m morok_relay.scripts.reaper

Or via systemd timer (preferred — see deploy/morok-reaper.{service,timer}).

What it does
------------
1. Walk /var/lib/morok/blobs/ for every file.
2. For each blob, derive envelope_id from the path (filename).
3. Check Redis: does morok:envelope:{envelope_id} still exist?
   - YES → blob is still queued; skip (will be reaped on a later run).
   - NO  → either delivered+acked, or Redis TTL expired it; safe to delete.
4. Also: any blob older than the hard ceiling (default 48h) is deleted
   regardless of Redis state — this is the privacy guarantee. Even if
   Redis is somehow stuck, the filesystem doesn't accumulate plaintext-
   accessible-by-disk-forensics encrypted blobs.

Secure-delete = overwrite with random bytes + unlink. On SSDs we rely on
periodic fstrim (separately scheduled) to actually erase the underlying
flash blocks.

Idempotent and safe to run repeatedly. Designed to be cheap when there's
nothing to reap.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from pathlib import Path

import redis.asyncio as redis_async

from ..blob_storage import secure_delete_blob
from ..config import get_settings


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
        # Filename should be a 64-hex envelope_id; anything else is foreign
        name = path.name
        if len(name) != 64 or not all(c in "0123456789abcdef" for c in name):
            continue
        yield path


async def reap_once() -> dict:
    """
    One pass over the blob directory. Returns a stats dict.

    Returns:
        {
            "scanned": int,         # total blob files found
            "still_queued": int,    # skipped because still in Redis queue
            "deleted_delivered": int,  # deleted because not in Redis (acked or queue-expired)
            "deleted_aged_out": int,   # deleted because older than hard ceiling
            "errors": int,
            "elapsed_seconds": float,
        }
    """
    settings = get_settings()
    now = int(time.time())
    age_limit_seconds = settings.message_ttl_hard_seconds

    stats = {
        "scanned": 0,
        "still_queued": 0,
        "deleted_delivered": 0,
        "deleted_aged_out": 0,
        "errors": 0,
    }
    start = time.monotonic()

    redis = redis_async.from_url(settings.redis_url, decode_responses=False)
    try:
        await redis.ping()
    except Exception as e:
        logger.error("Cannot connect to Redis: %s", e)
        await redis.aclose()
        stats["errors"] += 1
        stats["elapsed_seconds"] = time.monotonic() - start
        return stats

    try:
        for blob_path in _iter_blob_paths(settings.blob_dir):
            stats["scanned"] += 1
            envelope_id = blob_path.name

            try:
                # Aged-out check first — overrides everything else
                blob_age = now - int(blob_path.stat().st_mtime)
                if blob_age > age_limit_seconds:
                    deleted = await secure_delete_blob(envelope_id)
                    if deleted:
                        stats["deleted_aged_out"] += 1
                        logger.info(
                            "Aged-out blob deleted: %s (age=%ds)",
                            envelope_id[:16], blob_age,
                        )
                    continue

                # Otherwise, only delete if Redis no longer has the envelope
                exists = await redis.exists(f"morok:envelope:{envelope_id}")
                if exists:
                    stats["still_queued"] += 1
                    continue

                deleted = await secure_delete_blob(envelope_id)
                if deleted:
                    stats["deleted_delivered"] += 1
            except Exception as e:
                stats["errors"] += 1
                logger.exception("Reaper error on %s: %s", envelope_id[:16], e)
    finally:
        await redis.aclose()

    stats["elapsed_seconds"] = time.monotonic() - start
    return stats


def _setup_logging() -> None:
    """Plain stderr logging — journald captures it."""
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
        "morok-reaper done: scanned=%d still_queued=%d "
        "deleted_delivered=%d deleted_aged_out=%d errors=%d elapsed=%.2fs",
        stats["scanned"],
        stats["still_queued"],
        stats["deleted_delivered"],
        stats["deleted_aged_out"],
        stats["errors"],
        stats["elapsed_seconds"],
    )
    return 0 if stats["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
