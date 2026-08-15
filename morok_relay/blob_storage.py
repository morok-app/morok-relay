"""
Physical storage for encrypted message blobs.

Design principles
-----------------
1. Blobs are opaque bytes — relay never decrypts.
2. Stored as files on disk, NOT in Postgres. Postgres handles metadata only.
3. Filename is the envelope_id (sha256 of sender || recipient || ts || hash(blob)).
4. Sharded into subdirectories to avoid having millions of files in one dir.
5. Delete is physical: overwrite with random bytes, then unlink, then fsync.
   ВАЖЛИВО ПРО МЕЖІ: це BEST EFFORT, а не гарантоване стирання. На CoW-ФС
   (btrfs, ZFS) overwrite пише в НОВІ блоки — старі лишаються до GC. На SSD
   wear-leveling/FTL так само може зберегти старі блоки до TRIM. Реальна
   гарантія — full-disk encryption (LUKS) + знищення ключа; fstrim-таймер
   (deploy/morok-fstrim.*) лише скорочує вікно на SSD. Не обіцяємо "true
   erasure" ніде в публічних матеріалах.

Layout
------
    /var/lib/morok/blobs/
        ab/cd/abcdef1234...   (first 4 hex chars = directory)
        ef/01/ef0123456...

The first byte (2 hex chars) is the L1 dir, the second byte is L2.
Each L1 has 256 L2 subdirs, each L2 can hold thousands of blobs.
With 1M blobs we get ~15 blobs per L2 — manageable.
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
from pathlib import Path

from .config import get_settings

logger = logging.getLogger(__name__)


def _blob_path(envelope_id: str) -> Path:
    """Compute the on-disk path for a blob given its envelope_id (hex)."""
    settings = get_settings()
    if len(envelope_id) < 4 or not all(c in "0123456789abcdef" for c in envelope_id):
        raise ValueError(f"invalid envelope_id: {envelope_id!r}")
    return settings.blob_dir / envelope_id[:2] / envelope_id[2:4] / envelope_id


async def write_blob(envelope_id: str, blob: bytes) -> Path:
    """
    Write a blob to disk. Creates parent directories if needed.

    Atomic via temp+rename. Ім'я temp-файлу УНІКАЛЬНЕ на кожен виклик:
    детермінований `path.with_suffix(".tmp")` дозволяв двом паралельним
    POST одного конверта писати в ОДИН temp-файл (interleaved-вміст,
    падіння на rename). Тепер кожен writer має власний файл, а
    os.replace() атомарно кладе переможця на місце (програвший просто
    перезапише тим самим вмістом — envelope_id є хешем вмісту).
    """
    path = _blob_path(envelope_id)
    tmp_path = path.parent / f".{envelope_id}.{os.getpid()}.{secrets.token_hex(4)}.tmp"

    # Run blocking I/O in a thread so we don't stall the event loop
    def _write_sync():
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            with open(tmp_path, "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, path)
        except BaseException:
            # Не лишаємо сироту-temp при збої.
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    await asyncio.to_thread(_write_sync)
    return path


async def read_blob(envelope_id: str) -> bytes | None:
    """Read a blob from disk. Returns None if not found."""
    path = _blob_path(envelope_id)

    def _read_sync() -> bytes | None:
        if not path.exists():
            return None
        return path.read_bytes()

    return await asyncio.to_thread(_read_sync)


async def secure_delete_blob(envelope_id: str) -> bool:
    """
    Securely delete a blob: overwrite with random data, then unlink.

    Returns True if a blob was deleted, False if it didn't exist.

    Security note: overwrite+unlink is BEST-EFFORT everywhere. На CoW-ФС
    (btrfs/ZFS) overwrite не чіпає старих блоків; на SSD блоки живуть до
    TRIM (systemd-таймер morok-fstrim, добовий). Гарантоване стирання дає
    лише FDE (LUKS). Клієнтські обіцянки формулюємо відповідно.
    """
    path = _blob_path(envelope_id)

    def _delete_sync() -> bool:
        if not path.exists():
            return False
        try:
            size = path.stat().st_size
            # Overwrite with random bytes
            with open(path, "r+b") as f:
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())
            path.unlink()
            return True
        except OSError as e:
            logger.error("Failed to secure-delete blob %s: %s", envelope_id, e)
            return False

    return await asyncio.to_thread(_delete_sync)


async def blob_exists(envelope_id: str) -> bool:
    """Cheap existence check."""
    path = _blob_path(envelope_id)
    return await asyncio.to_thread(path.exists)
