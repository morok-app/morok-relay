#!/usr/bin/env python3
"""
Навантажувальний профіль релея (аудит 4, четвертий клас — ресурси).

ЧОМУ ЦЕ ОКРЕМИЙ СКРИПТ, А НЕ PYTEST. Тут немає assert'ів «правильно/
неправильно» — тут ВИМІРЮВАННЯ. Питання, на які жоден аудит читанням
коду не відповість: скільки пам'яті Redis з'їдає один користувач,
скільки триває fan-out на 500 осіб, як росте латентність inbox'а при
глибині 5000. Відповіді потрібні, щоб планувати залізо і знати, коли
`maxmemory 2gb` стане тісним.

Запуск (на ТЕСТОВОМУ Redis, не на бойовому!):

    redis-server --port 6399 --daemonize yes
    python tools/load_profile.py

    # або проти іншого інстансу:
    MOROK_LOAD_REDIS_URL=redis://localhost:6399/9 python tools/load_profile.py

Скрипт сам чистить за собою (FLUSHDB своєї логічної БД на початку і в
кінці) і НІКОЛИ не торкається db 0.
"""
from __future__ import annotations

import asyncio
import os
import statistics
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("MOROK_RELAY_PRIVKEY_HEX", "1f" * 32)
os.environ.setdefault("MOROK_RELAY_PUBKEY_HEX", "2e" * 32)

import redis.asyncio as redis_async  # noqa: E402

from morok_relay import queue as q  # noqa: E402

REDIS_URL = os.environ.get("MOROK_LOAD_REDIS_URL", "redis://localhost:6399/9")
SENDER = "99" * 32


# ── дрібні утиліти ───────────────────────────────────────────────────────
def _pk(i: int) -> str:
    return f"{i:064x}"


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


async def _used_memory(r) -> int:
    info = await r.info("memory")
    return int(info["used_memory"])


def _report(name: str, samples: list[float]) -> None:
    """Латентність показуємо через медіану і p95 — середнє бреше на хвостах."""
    if not samples:
        return
    ms = sorted(s * 1000 for s in samples)
    p95 = ms[int(len(ms) * 0.95)] if len(ms) > 1 else ms[0]
    print(
        f"  {name:<38} медіана {statistics.median(ms):7.2f} ms   "
        f"p95 {p95:7.2f} ms   макс {ms[-1]:7.2f} ms"
    )


async def _send_dm(r, recipient: str, eid: str) -> None:
    await q.enqueue_envelope(
        r,
        envelope_id=eid,
        sender_pubkey_hex=SENDER,
        recipient_pubkey_hex=recipient,
        timestamp=int(time.time()),
        ttl_seconds=3600,
        signature_hex="ff" * 64,
        hard_ceiling_seconds=86400,
    )


# ── сценарії ─────────────────────────────────────────────────────────────
async def scenario_group_fanout(r) -> None:
    """Скільки коштує розсилка в групу різного розміру."""
    print("\n── Груповий fan-out ─────────────────────────────────────────")
    print("  (після фіксу HIGH-2 має рости майже лінійно за обсягом даних,")
    print("   а не квадратично за round-trip'ами)")

    for size in (10, 50, 200, 500):
        members = [_pk(i) for i in range(1, size + 1)]
        await r.flushdb()

        samples = []
        for n in range(5):
            eid = f"{n:02x}" + "ab" * 31
            t0 = time.perf_counter()
            await q.enqueue_envelope_for_recipients(
                r,
                envelope_id=eid,
                sender_pubkey_hex=SENDER,
                recipient_pubkeys_hex=members,
                timestamp=int(time.time()),
                ttl_seconds=3600,
                signature_hex="ff" * 64,
                hard_ceiling_seconds=86400,
                group_id="11111111-2222-3333-4444-555555555555",
            )
            samples.append(time.perf_counter() - t0)

        per_member = statistics.median(samples) * 1000 / size
        _report(f"група {size:>3} осіб, 1 повідомлення", samples)
        print(f"  {'':<38} → {per_member:.3f} ms на одного одержувача")


async def scenario_memory_per_user(r) -> None:
    """Скільки Redis-пам'яті коштує один користувач із заповненим inbox'ом."""
    print("\n── Пам'ять Redis ────────────────────────────────────────────")

    await r.flushdb()
    base = await _used_memory(r)

    users = 500
    msgs_each = 20
    for u in range(users):
        recipient = _pk(u + 1)
        for m in range(msgs_each):
            await _send_dm(r, recipient, f"{u:04x}{m:04x}" + "cd" * 28)

    after = await _used_memory(r)
    total = after - base
    print(f"  {users} користувачів × {msgs_each} конвертів = "
          f"{users * msgs_each} конвертів")
    print(f"  приріст used_memory: {_fmt_bytes(total)}")
    print(f"  → {_fmt_bytes(total / users)} на користувача")
    print(f"  → {_fmt_bytes(total / (users * msgs_each))} на конверт")

    # Екстраполяція — головна цифра для планування заліза.
    for scale in (10_000, 100_000):
        est = total / users * scale
        print(f"  прогноз для {scale:>7,} користувачів (по {msgs_each} конвертів): "
              f"{_fmt_bytes(est)}")

    print("\n  ПРИМІТКА: це ЛИШЕ метадані черги. Самі блоби лежать на диску")
    print("  (blob_storage), у Redis їх немає. Реальний профіль залежить від")
    print("  того, скільки конвертів у середньому висить недоставленими.")


async def scenario_deep_inbox(r) -> None:
    """Латентність читання inbox'а при різній глибині черги."""
    print("\n── Глибокий inbox ───────────────────────────────────────────")
    print(f"  (стеля MAX_INBOX_QUEUE_DEPTH = {q.MAX_INBOX_QUEUE_DEPTH})")

    for depth in (10, 100, 1000, 5000):
        await r.flushdb()
        recipient = _pk(777)
        now = int(time.time())

        # Наповнюємо безпосередньо, щоб не міряти час запису.
        async with r.pipeline(transaction=False) as pipe:
            for i in range(depth):
                pipe.zadd(f"morok:inbox:{recipient}", {f"env{i:06d}": now + 3600})
                pipe.set(f"morok:envelope:env{i:06d}", b'{"from":"x","to":"y"}', ex=3600)
            await pipe.execute()

        samples = []
        for _ in range(5):
            t0 = time.perf_counter()
            await q.list_inbox(r, recipient, limit=200)
            samples.append(time.perf_counter() - t0)

        _report(f"list_inbox(limit=200) при глибині {depth:>4}", samples)


async def scenario_write_throughput(r) -> None:
    """Скільки DM-конвертів на секунду тягне один процес."""
    print("\n── Пропускна здатність запису ───────────────────────────────")

    await r.flushdb()
    total = 2000
    concurrency = 50

    async def worker(worker_id: int, count: int) -> None:
        for i in range(count):
            await _send_dm(
                r, _pk(worker_id + 1), f"{worker_id:04x}{i:04x}" + "ef" * 28,
            )

    per_worker = total // concurrency
    t0 = time.perf_counter()
    await asyncio.gather(*[worker(w, per_worker) for w in range(concurrency)])
    elapsed = time.perf_counter() - t0

    print(f"  {total} конвертів у {concurrency} паралельних потоках")
    print(f"  за {elapsed:.2f} с → {total / elapsed:,.0f} конвертів/с")
    print("  (одна нода Redis, локальна мережа — на проді буде менше)")


async def scenario_tombstone_cost(r) -> None:
    """Скільки додали tombstone'и з батчу 4."""
    print("\n── Вартість tombstone'ів (батч 4) ───────────────────────────")

    await r.flushdb()
    base = await _used_memory(r)
    n = 1000
    for i in range(n):
        await _send_dm(r, _pk(1), f"{i:04x}" + "11" * 30)
    after = await _used_memory(r)

    tomb_keys = 0
    async for _ in r.scan_iter("morok:env_tomb:*", count=1000):
        tomb_keys += 1

    print(f"  {n} конвертів → {tomb_keys} tombstone'ів")
    print(f"  сумарний приріст: {_fmt_bytes(after - base)}")
    print("  tombstone живе довше за конверт (TTL + 7 днів) — саме він")
    print("  визначає нижню межу пам'яті при сплеску трафіку.")


async def main() -> None:
    if REDIS_URL.rstrip("/").endswith("/0"):
        print("ВІДМОВА: db 0 схожа на бойову. Вкажи іншу логічну БД, "
              "напр. redis://localhost:6399/9")
        sys.exit(1)

    r = redis_async.from_url(REDIS_URL, max_connections=250)
    try:
        await r.ping()
    except Exception as e:
        print(f"Redis недоступний за {REDIS_URL}: {e}")
        print("Підніми тестовий: redis-server --port 6399 --daemonize yes")
        sys.exit(1)

    print("=" * 64)
    print(f"MOROK RELAY — навантажувальний профіль  ({REDIS_URL})")
    print("=" * 64)

    try:
        await scenario_group_fanout(r)
        await scenario_memory_per_user(r)
        await scenario_deep_inbox(r)
        await scenario_write_throughput(r)
        await scenario_tombstone_cost(r)
    finally:
        await r.flushdb()
        await r.aclose()

    print("\n" + "=" * 64)
    print("Готово. Тестова БД очищена.")
    print("=" * 64)


if __name__ == "__main__":
    asyncio.run(main())
