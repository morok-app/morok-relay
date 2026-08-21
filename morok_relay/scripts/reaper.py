"""
Blob and group reaper — secure-delete expired data.

Run manually:
    python -m morok_relay.scripts.reaper                # indexed only
    python -m morok_relay.scripts.reaper --full-scan     # + filesystem scan

Or via systemd timer (preferred — see deploy/morok-reaper.{service,timer}
for the frequent indexed run, morok-reaper-fullscan.{service,timer} for
the rare filesystem safety-net run).

Що робить (MEDIUM з фрешевого аудиту — "reaper масштабується як повний
filesystem scan" — виправлено)
------------------------------------------------------------------------
1. ОСНОВНИЙ, ЧАСТИЙ прохід (reap_blobs_indexed): читає прострочені
   candidates з Redis ZSET (morok:blob_expiry_index, заповнюється
   в queue.py на кожному enqueue), а не сканує диск. O(K), не O(усі
   файли).
2. РІДКІСНИЙ safety-net прохід (reap_blobs_full_scan, --full-scan):
   стара логіка — rglob() над УСІМ blob_dir, для orphan-файлів, яких
   індекс не бачив (crash між write_blob і enqueue; blob'и, записані
   ДО деплою indexed-версії).
3. Soft-delete groups whose expires_at has passed. The actual DB row is
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
from ..queue import _BLOB_EXPIRY_INDEX_KEY


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


# Скільки чекати, перш ніж вважати temp-файл покинутим. Запис блоба —
# операція на мілісекунди, тож година це величезний запас; менше брати
# небезпечно (можна знести temp запису, що саме йде).
STALE_TMP_AGE_SECONDS = 3600


def reap_stale_temp_files(blob_dir: Path, now: int) -> dict:
    """
    Прибирає покинуті temp-файли запису блобів.

    ЧОМУ ЦЕ ПОТРІБНО. write_blob пише в УНІКАЛЬНИЙ temp
    (`.{envelope_id}.{pid}.{random}.tmp`), щоб два паралельні записи
    одного конверта не лізли в один файл. Зворотний бік: якщо процес
    помирає між створенням temp і os.replace() (SIGKILL, OOM, падіння
    диска), сирота лишається — і кожен наступний збій додає НОВИЙ файл,
    а не перезаписує старий. `_iter_blob_paths` їх свідомо пропускає
    (щоб не знести запис, що триває), тож без цієї функції їх не
    прибирає ніхто, і місце на диску тече.

    Видаляємо звичайним unlink, без перезапису: temp-сирота — це
    ЗАШИФРОВАНИЙ блоб, який ніколи не був доступний користувачам;
    гарантії secure-delete тут не сильніші за FDE (див. blob_storage).
    """
    stats = {"tmp_scanned": 0, "tmp_deleted": 0, "tmp_errors": 0}
    if not blob_dir.exists():
        return stats

    for path in blob_dir.rglob("*.tmp"):
        if not path.is_file():
            continue
        stats["tmp_scanned"] += 1
        try:
            age = now - int(path.stat().st_mtime)
            if age < STALE_TMP_AGE_SECONDS:
                continue          # запис може тривати просто зараз
            path.unlink()
            stats["tmp_deleted"] += 1
            logger.info("Removed stale temp blob %s (age %ds)", path.name, age)
        except FileNotFoundError:
            # Хтось прибрав раніше (нормальна гонка з успішним записом).
            continue
        except OSError as e:
            stats["tmp_errors"] += 1
            logger.warning("Failed to remove stale temp %s: %s", path.name, e)

    return stats


async def reap_blobs_indexed(redis: redis_async.Redis) -> dict:
    """
    Основний, ЧАСТИЙ прохід (MEDIUM з фрешевого аудиту — "reaper
    масштабується як повний filesystem scan"). Читає прострочені
    candidates з Redis ZSET (заповнюється в queue.py на кожному
    enqueue, score=expires_at) замість rglob() над УСІМ blob_dir.

    Вартість: O(K log N), де K — кількість реально прострочених
    candidates, N — розмір індексу. НЕ залежить від загальної
    кількості файлів на диску, на відміну від filesystem-scan (де
    вартість завжди O(усі файли), навіть якщо прострочений лише один).

    Що НЕ ловить: файли, які фізично лежать на диску, але ніколи не
    потрапили в індекс (crash між write_blob і enqueue; blob'и,
    записані ДО деплою цього фіксу). Для них лишається
    reap_blobs_full_scan() — рідкісний (не щогодинний) safety-net.
    """
    stats = {
        "indexed_candidates": 0,
        "indexed_deleted": 0,
        "indexed_still_queued": 0,
        "indexed_errors": 0,
    }
    now = int(time.time())

    raw_candidates = await redis.zrangebyscore(_BLOB_EXPIRY_INDEX_KEY, 0, now)
    stats["indexed_candidates"] = len(raw_candidates)

    for raw_eid in raw_candidates:
        envelope_id = (
            raw_eid.decode("utf-8") if isinstance(raw_eid, bytes) else raw_eid
        )
        try:
            # Той самий сигнал, що й у full-scan шляху: meta existence
            # означає "ще в черзі, не чіпати". Може статись рідко —
            # округлення score трохи відстає від реального Redis TTL
            # meta-ключа; не страшно, просто пропускаємо цей прохід.
            if await redis.exists(f"morok:envelope:{envelope_id}"):
                stats["indexed_still_queued"] += 1
                continue
            deleted = await secure_delete_blob(envelope_id)
            if deleted:
                stats["indexed_deleted"] += 1
        except Exception as e:
            stats["indexed_errors"] += 1
            logger.exception(
                "Indexed reaper error on %s: %s", envelope_id[:16], e,
            )
        finally:
            # Прибираємо з індексу НЕЗАЛЕЖНО від результату — інакше
            # той самий candidate повертався б щоразу: ZRANGEBYSCORE
            # 0..now завжди включає старі score.
            try:
                await redis.zrem(_BLOB_EXPIRY_INDEX_KEY, raw_eid)
            except Exception:
                pass

    return stats


async def reap_blobs_full_scan(redis: redis_async.Redis) -> dict:
    """
    Рідкісний (не щогодинний) safety-net прохід — повний filesystem
    scan, стара логіка без змін. Ловить те, що індекс пропустив:
    orphan-файли, які фізично лежать на диску, але ніколи не
    потрапили в morok:blob_expiry_index (crash між write_blob і
    enqueue; blob'и, записані ДО деплою reap_blobs_indexed).
    """
    settings = get_settings()
    now = int(time.time())

    stats = {
        "blobs_scanned": 0,
        "blobs_still_queued": 0,
        "blobs_deleted_delivered": 0,
        "blobs_deleted_aged_out": 0,
        "blob_errors": 0,
    }
    # Покинуті temp-файли: інакше їх не прибирає ніхто (див. функцію).
    stats.update(reap_stale_temp_files(settings.blob_dir, now))

    # Запасний віковий ліміт: НЕ фіксовані 24 години, а найдовший
    # можливий TTL у системі. Пошта живе в черзі 7 діб (mail_ttl_seconds),
    # тому вирізати blob за 24 год означало б знищувати листи, які ще
    # чекають на отримувача (K8: лист видно у вхідних, але GET дає 404).
    # Беремо максимум із двох стель + добу фори, щоб покрити ще й
    # федеративні конверти й розсинхрон годинника.
    hard_age_limit = max(
        settings.message_ttl_hard_seconds,
        settings.mail_ttl_seconds,
    ) + 86400

    for blob_path in _iter_blob_paths(settings.blob_dir):
        stats["blobs_scanned"] += 1
        envelope_id = blob_path.name

        try:
            # ПОРЯДОК ВАЖЛИВИЙ: спершу питаємо чергу, потім вік.
            # Поки конверт лежить у Redis-черзі (тобто отримувач ще не
            # забрав його), blob чіпати НЕ МОЖНА — незалежно від віку
            # файлу. Раніше вікова перевірка стояла першою й затирала
            # поштовий blob на 25-й годині, хоча в черзі він живе 7 діб.
            exists = await redis.exists(f"morok:envelope:{envelope_id}")
            if exists:
                stats["blobs_still_queued"] += 1
                continue

            # Конверта в черзі немає. Це означає одне з двох:
            #   1) отримувач його забрав і ack-нув (доставлено) →
            #      blob можна прибирати;
            #   2) конверт протух і випав із черги, а файл лишився сиротою.
            # Обидва випадки — на видалення. Але додатковий віковий
            # запобіжник лишаємо: якщо з якоїсь причини Redis відповів
            # порожньо помилково (флаш, міграція), СВІЖИЙ blob не чіпаємо,
            # даємо йому дожити до природної стелі.
            blob_age = now - int(blob_path.stat().st_mtime)
            if blob_age <= hard_age_limit:
                # молодший за стелю й не в черзі → доставлений сирота
                deleted = await secure_delete_blob(envelope_id)
                if deleted:
                    stats["blobs_deleted_delivered"] += 1
                continue

            # старший за будь-який мислимий TTL → гарантовано сміття
            deleted = await secure_delete_blob(envelope_id)
            if deleted:
                stats["blobs_deleted_aged_out"] += 1
                logger.info(
                    "Aged-out orphan blob deleted: %s (age=%ds)",
                    envelope_id[:16], blob_age,
                )
            continue

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


async def reap_once(full_scan: bool = False) -> dict:
    """
    Run blob and group reaping in one pass.

    full_scan=False (типовий, частий прохід — щогодинний timer):
    лише reap_blobs_indexed(), швидкий, Redis-based.

    full_scan=True (рідкісний прохід — окремий, нечастий timer):
    ОБИДВА — indexed (як завжди) ПЛЮС filesystem safety-net для
    orphan-файлів, яких індекс не бачив.
    """
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
        blob_stats = await reap_blobs_indexed(redis)
        if full_scan:
            full_scan_stats = await reap_blobs_full_scan(redis)
            blob_stats.update(full_scan_stats)
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
    full_scan = "--full-scan" in sys.argv[1:]
    logger.info(
        "morok-reaper starting (mode=%s)",
        "full-scan" if full_scan else "indexed",
    )
    stats = await reap_once(full_scan=full_scan)
    logger.info(
        "morok-reaper done: indexed_candidates=%d indexed_deleted=%d "
        "fullscan_scanned=%d fullscan_delivered=%d fullscan_aged=%d "
        "groups_expired=%d errors=%d elapsed=%.2fs",
        stats.get("indexed_candidates", 0),
        stats.get("indexed_deleted", 0),
        stats.get("blobs_scanned", 0),
        stats.get("blobs_deleted_delivered", 0),
        stats.get("blobs_deleted_aged_out", 0),
        stats.get("groups_expired", 0),
        stats.get("indexed_errors", 0) + stats.get("blob_errors", 0)
        + stats.get("group_errors", 0),
        stats.get("elapsed_seconds", 0.0),
    )
    total_errors = (
        stats.get("indexed_errors", 0)
        + stats.get("blob_errors", 0)
        + stats.get("group_errors", 0)
    )
    return 0 if total_errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
