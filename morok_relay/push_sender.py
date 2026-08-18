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
        # pywebpush: рядок трактується як сирий base64url-ключ, а PEM-вміст
        # ламається ("header too long"). Передаємо ШЛЯХ — тоді бібліотека
        # сама читає файл як PEM (Vapid.from_file).
        path.read_text()  # sanity: файл читається
        _PRIVATE_KEY_CACHE = str(path)
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


# ─── FCM (нативний Android) ──────────────────────────────────────────
#
# Web push шифрує payload end-to-end до браузера (RFC 8291), тому туди
# можна класти from_username. FCM-повідомлення читається інфраструктурою
# Google — тому для FCM payload максимально порожній: generic title/body,
# БЕЗ відправника, БЕЗ group_id, без жодних метаданих. Користувач
# відкриває застосунок і бачить, що прийшло, через звичайний WS/інбокс.

_FCM_CREDS_CACHE: tuple | None = None  # (credentials, project_id)


def _load_fcm_credentials():
    """Service-account credentials + project id. None => FCM вимкнено."""
    global _FCM_CREDS_CACHE
    if _FCM_CREDS_CACHE is not None:
        return _FCM_CREDS_CACHE

    settings = get_settings()
    path = Path(settings.fcm_service_account_path)
    if not path.is_file():
        return None
    try:
        from google.oauth2 import service_account  # lazy: optional dep

        info = json.loads(path.read_text())
        creds = service_account.Credentials.from_service_account_info(
            info, scopes=["https://www.googleapis.com/auth/firebase.messaging"],
        )
        project_id = info.get("project_id")
        if not project_id:
            logger.warning("FCM service account has no project_id, disabled")
            return None
        _FCM_CREDS_CACHE = (creds, project_id)
        return _FCM_CREDS_CACHE
    except Exception as e:
        logger.warning("FCM service account unusable: %s", e)
        return None


def _send_fcm_blocking(token: str) -> str:
    """
    Send one generic FCM notification. Returns 'ok' | 'gone' | 'error'.
    Runs on the push thread-pool (google-auth transport is sync).
    """
    loaded = _load_fcm_credentials()
    if loaded is None:
        return "error"
    creds, project_id = loaded
    try:
        from google.auth.transport.requests import AuthorizedSession

        session = AuthorizedSession(creds)  # auto-refreshes OAuth token
        resp = session.post(
            f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send",
            json={
                "message": {
                    "token": token,
                    "notification": {
                        "title": "Morok",
                        "body": "Нове повідомлення",
                    },
                    "android": {
                        "priority": "HIGH",
                        "notification": {
                            "channel_id": "messages_v2",
                        },
                    },
                }
            },
            timeout=10,
        )
        if resp.status_code == 200:
            return "ok"
        # 404 UNREGISTERED / 400 invalid token => підписка мертва, чистимо
        if resp.status_code in (400, 404):
            body = resp.text or ""
            if "UNREGISTERED" in body or "INVALID_ARGUMENT" in body or resp.status_code == 404:
                return "gone"
        logger.warning("FCM send failed (%d): %.200s", resp.status_code, resp.text)
        return "error"
    except Exception as e:
        logger.warning("FCM send exception: %s", e)
        return "error"


def schedule_push(
    redis,
    recipient_pubkeys_hex: list[str],
    *,
    sender_username: str | None,
    group_id: str | None = None,
    kind: str | None = None,
) -> None:
    """
    Fire-and-forget обгортка над trigger_push (аудит зовн. №3, HIGH).

    Кожен виклик `await trigger_push(...)` у api/ стояв на critical
    path запиту — попри власний докстрінг trigger_push, що прямо каже
    "caller must never await this". webpush() б'є на endpoint зовнішнім
    HTTP-запитом; клієнт, що відправляє повідомлення, чекав на цю
    мережеву round-trip перш ніж отримати підтвердження власної
    відправки.

    НЕ приймає db-сесію ззовні: FastAPI-шний DBSession — request-scoped
    і закривається одразу після відповіді. Передати його в
    create_task() означало б, що фонова задача працює з СЕСІЄЮ ПІСЛЯ
    ЇЇ ЗАКРИТТЯ — гонка з фіналізацією запиту й падіння на закритому
    з'єднанні. Замість цього відкриваємо ОКРЕМУ сесію з того самого
    _session_factory, яким користується deps.get_session, — з чітким
    життєвим циклом, прив'язаним до самої задачі.
    """
    task = asyncio.create_task(_run_push_in_own_session(
        redis, recipient_pubkeys_hex,
        sender_username=sender_username, group_id=group_id, kind=kind,
    ))
    task.add_done_callback(_log_push_task_error)


async def _run_push_in_own_session(
    redis,
    recipient_pubkeys_hex: list[str],
    *,
    sender_username: str | None,
    group_id: str | None,
    kind: str | None,
) -> None:
    from .db import _session_factory
    if _session_factory is None:
        logger.warning("schedule_push: db not initialized, dropping push")
        return
    async with _session_factory() as db:
        await trigger_push(
            db, redis, recipient_pubkeys_hex,
            sender_username=sender_username, group_id=group_id, kind=kind,
        )


def _log_push_task_error(task: "asyncio.Task") -> None:
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.warning("Background push task failed: %s", exc)


async def trigger_push(
    db: AsyncSession,
    redis,
    recipient_pubkeys_hex: list[str],
    *,
    sender_username: str | None,
    group_id: str | None = None,
    kind: str | None = None,
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

    webpush_pem = None
    if settings.vapid_public_key_b64:
        webpush_pem = _load_private_key()
    fcm_ready = _load_fcm_credentials() is not None

    if webpush_pem is None and not fcm_ready:
        return  # Push globally disabled (ні webpush, ні FCM)

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
        "kind": kind,
        "ts": int(time.time()),
    })

    loop = asyncio.get_running_loop()
    gone_endpoints: list[tuple[bytes, str]] = []  # (pubkey, endpoint)
    now = int(time.time())

    async def send_one(row: PushSubscription) -> None:
        if getattr(row, "platform", "webpush") == "fcm":
            if not fcm_ready:
                return
            result = await loop.run_in_executor(
                _executor, _send_fcm_blocking, row.endpoint,
            )
        else:
            if webpush_pem is None:
                return
            sub_dict = {
                "endpoint": row.endpoint,
                "keys": {"p256dh": row.p256dh, "auth": row.auth},
            }
            result = await loop.run_in_executor(
                _executor,
                _send_blocking,
                sub_dict, payload, webpush_pem, settings.vapid_subject,
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
