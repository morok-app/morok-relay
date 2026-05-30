"""
Web push notification delivery.

We use the pywebpush library, which is synchronous, so each push is
dispatched on a small thread-pool. The number of pushes per message is
small (one per recipient subscription), so this stays cheap.

Push payloads are deliberately MINIMAL — relay doesn't have plaintext
of the message anyway. We send:
    { from_username: "satoshi"|null, group_id: "uuid"|null, ts: int }

The Service Worker on the client reads this and shows a generic
"Нове повідомлення від @satoshi" notification. The real message body
stays encrypted in the user's inbox until they open the app.

Dead subscriptions (404/410 from the push service) are removed from
the DB automatically — that's how subscription cleanup happens. No
separate sweeper task is needed.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pywebpush import WebPushException, webpush
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .models import PushSubscription

logger = logging.getLogger(__name__)

# Small pool: pushes are network-bound but short. 4 threads is plenty
# for the throughput a single relay sees.
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="push")

_PRIVATE_KEY_CACHE: str | None = None


def _load_private_key() -> str | None:
    """Read VAPID PEM from disk, cache it. Returns None if unreadable."""
    global _PRIVATE_KEY_CACHE
    if _PRIVATE_KEY_CACHE is not None:
        return _PRIVATE_KEY_CACHE

    settings = get_settings()
    path = Path(settings.vapid_private_key_path)
    if not path.is_file():
        logger.info("VAPID private key not found at %s, push disabled", path)
        return None
    try:
        _PRIVATE_KEY_CACHE = path.read_text()
        return _PRIVATE_KEY_CACHE
    except OSError as e:
        logger.warning("VAPID private key unreadable: %s", e)
        return None


def _send_blocking(
    sub_dict: dict,
    payload: str,
    vapid_private_pem: str,
    vapid_subject: str,
) -> str:
    """
    Synchronous push. Runs in thread pool.

    Returns:
      "ok"   — push accepted by upstream
      "gone" — subscription is dead, caller should delete the row
      "err"  — transient failure, leave subscription alone
    """
    try:
        webpush(
            subscription_info=sub_dict,
            data=payload,
            vapid_private_key=vapid_private_pem,
            vapid_claims={"sub": vapid_subject},
            ttl=60,
        )
        return "ok"
    except WebPushException as e:
        status = getattr(e.response, "status_code", None) if e.response else None
        if status in (404, 410):
            return "gone"
        logger.warning("push send failed (status=%s): %s", status, e)
        return "err"
    except Exception as e:
        logger.warning("push send unexpected error: %s", e)
        return "err"


async def trigger_push(
    db: AsyncSession,
    redis,
    recipient_pubkeys_hex: list[str],
    *,
    sender_username: str | None,
    group_id: str | None = None,
) -> None:
    """
    Fan out a push notification to every subscription of every recipient
    that is NOT currently online.

    Online detection: Redis counter morok:ws:active:{pubkey}. The inbox
    WS endpoint increments on connect and decrements on disconnect.
    Counter > 0 means at least one tab is open — skip push, the user
    will see the message in real-time.

    Best-effort: any errors are swallowed. Caller (api/messages.py,
    api/groups.py) must never await this on the critical path.
    """
    settings = get_settings()
    if not settings.vapid_public_key_b64:
        return  # Push globally disabled

    private_pem = _load_private_key()
    if private_pem is None:
        return

    # Filter out recipients with active WS
    offline: list[str] = []
    for pk in recipient_pubkeys_hex:
        try:
            count_raw = await redis.get(f"morok:ws:active:{pk}")
        except Exception:
            count_raw = None
        if count_raw is None:
            offline.append(pk)
        else:
            try:
                if int(count_raw) <= 0:
                    offline.append(pk)
            except ValueError:
                offline.append(pk)

    if not offline:
        return

    # Load subscriptions for all offline recipients
    pubkey_bytes = [bytes.fromhex(p) for p in offline]
    stmt = select(PushSubscription).where(PushSubscription.pubkey.in_(pubkey_bytes))
    rows = (await db.execute(stmt)).scalars().all()
    if not rows:
        return

    payload = json.dumps({
        "from_username": sender_username,
        "group_id": group_id,
        "ts": int(time.time()),
    })

    loop = asyncio.get_running_loop()
    gone_endpoints: list[tuple[bytes, str]] = []  # (pubkey, endpoint)
    now = int(time.time())

    async def send_one(row: PushSubscription) -> None:
        sub_dict = {
            "endpoint": row.endpoint,
            "keys": {"p256dh": row.p256dh, "auth": row.auth},
        }
        result = await loop.run_in_executor(
            _executor,
            _send_blocking,
            sub_dict, payload, private_pem, settings.vapid_subject,
        )
        if result == "gone":
            gone_endpoints.append((row.pubkey, row.endpoint))
        elif result == "ok":
            row.last_used_at = now

    await asyncio.gather(*(send_one(r) for r in rows), return_exceptions=True)

    # Sweep dead subscriptions
    if gone_endpoints:
        for pubkey, endpoint in gone_endpoints:
            await db.execute(
                delete(PushSubscription).where(
                    PushSubscription.pubkey == pubkey,
                    PushSubscription.endpoint == endpoint,
                )
            )
        try:
            await db.flush()
        except Exception as e:
            logger.warning("failed to flush dead-subscription cleanup: %s", e)

    logger.info(
        "push fan-out: %d recipients, %d subs, %d removed",
        len(offline), len(rows), len(gone_endpoints),
    )
