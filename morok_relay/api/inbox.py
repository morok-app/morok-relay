"""
WebSocket inbox — real-time delivery of envelope notifications.

URL: wss://relay1.morok.app/ws/v1/inbox?token=<session_token>

Why query token instead of Authorization header
-----------------------------------------------
Browsers do not allow setting custom headers on WebSocket connections
(unlike HTTP). Native clients can, but to keep parity we accept the token
as a query parameter. Token is only used for the handshake — once the
connection is established, no further auth is needed for THIS connection.

What the server pushes
----------------------
On connection: catch-up frame with all pending envelopes.
After that: one frame per new envelope as it arrives, via Redis pub/sub.

Frame format
------------
    { "type": "catchup", "envelopes": [ {envelope metadata}, ... ] }
    { "type": "new", "envelope": { envelope metadata } }
    { "type": "ping" }   — server heartbeat every 30s
    { "type": "error", "detail": "..." }

Client should:
- Send {"type": "ack", "envelope_id": "..."} after successful processing
  → equivalent to DELETE /messages/{id}
- Send {"type": "pong"} in response to "ping" (or any keepalive)
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import uuid

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from ..config import get_settings
from ..deps import get_redis
from ..queue import acknowledge_envelope, get_envelope_meta, list_inbox
from ..rate_limit import release_ws_slot, reserve_ws_slot, refresh_ws_slot
from ..sessions import verify_session_token

logger = logging.getLogger(__name__)

# Коди закриття WebSocket у застосунковому діапазоні (4000-4999).
# Клієнт розрізняє їх, щоб обрати правильну реакцію:
#   4001 — токен недійсний/протух → перелогінитись і перепідключитись
#   4002 — вичерпано ліміт паралельних з'єднань → чекати довше, НЕ логінитись
WS_CLOSE_AUTH_FAILED = 4001
WS_CLOSE_TOO_MANY_CONNECTIONS = 4002

router = APIRouter(tags=["inbox"])


# Time between server-side pings; client should respond with pong.
PING_INTERVAL_SECONDS = 30


@router.websocket("/inbox")
async def inbox_socket(
    websocket: WebSocket,
    token: str = Query(..., min_length=64, max_length=64),
) -> None:
    """
    Real-time delivery channel for authenticated users.

    Handshake: client connects with ?token=<session_token>. Server verifies,
    accepts the connection, sends a catch-up frame with current inbox,
    then forwards new envelopes as they arrive.
    """
    redis = get_redis()

    # 1. Authenticate via session token
    #
    # ВАЖЛИВО: спершу accept(), і лише потім close(code=...).
    # У Starlette close() ДО accept() не надсилає WebSocket-кадр закриття —
    # рукостискання завершується як HTTP 403, і клієнт бачить код 1006
    # (abnormal closure). Через це протухла сесія, вичерпаний ліміт
    # з'єднань і звичайний обрив мережі виглядали для клієнта ОДНАКОВО:
    # він не знав, що треба перелогінитись, і мовчки крутив реконекти,
    # поки застосунок не перезапустять.
    #
    # Приймаємо з'єднання на мілісекунди, щоб мати змогу передати причину,
    # і одразу закриваємо. Коди в діапазоні 4000-4999 зарезервовані для
    # застосунку саме для таких випадків.
    session = await verify_session_token(redis, token)
    if session is None:
        await websocket.accept()
        await websocket.close(code=WS_CLOSE_AUTH_FAILED, reason="auth_failed")
        return

    pubkey_hex = session.pubkey_hex
    # Хеш власного токена: за ним відрізняємо адресовану саме нам подію
    # session_revoked від такої ж події для іншого пристрою користувача
    # (канал pub/sub спільний на весь акаунт).
    _my_token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    # Enforce the per-pubkey concurrent-connection cap. The helper and
    # the setting existed since day one but were never wired in — without
    # this, one account could open unlimited parallel sockets (each one
    # holds a Redis pub/sub connection + a server task: cheap DoS).
    settings = get_settings()
    connection_id = str(uuid.uuid4())
    slot_ok = await reserve_ws_slot(
        redis, pubkey_hex, connection_id,
        settings.rate_limit_ws_connections_per_pubkey,
    )
    if not slot_ok:
        # ОКРЕМИЙ код: це НЕ проблема з автентифікацією. Якщо віддати той
        # самий 1008/4001, клієнт вирішить, що сесія протухла, піде
        # перелогінюватись — і повернеться в ту саму стіну, бо слоти
        # зайняті іншими вкладками/пристроями. Правильна реакція —
        # зачекати довше, а не оновлювати токен.
        await websocket.accept()
        await websocket.close(code=WS_CLOSE_TOO_MANY_CONNECTIONS, reason="too_many_connections")
        return

    await websocket.accept()
    logger.info("inbox WebSocket open: pubkey=%s...", pubkey_hex[:8])

    # Track this connection in Redis so push fanout can skip users who
    # have at least one tab open. Counter has a TTL so a crashed server
    # doesn't leave stale "online" state forever.
    ws_active_key = f"morok:ws:active:{pubkey_hex}"
    try:
        await redis.incr(ws_active_key)
        # Короткий TTL: якщо з'єднання померло без FIN (вбитий застосунок,
        # обрив мережі), лічильник зникне за ~90с і пуші підуть. Живі
        # з'єднання оновлюють TTL у pinger_task кожні 30с.
        await redis.expire(ws_active_key, 90)
    except Exception as e:
        logger.warning("ws-active incr failed for %s: %s", pubkey_hex[:8], e)

    # 2. Send catch-up frame
    try:
        envelopes = await list_inbox(redis, pubkey_hex, limit=200)
        await websocket.send_json({
            "type": "catchup",
            "envelopes": envelopes,
            "count": len(envelopes),
        })
    except Exception as e:
        logger.exception("Failed catchup for %s: %s", pubkey_hex[:8], e)
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        await release_ws_slot(redis, pubkey_hex, connection_id)
        return

    # 3. Subscribe to pub/sub channel for this recipient
    pubsub = redis.pubsub()
    channel_name = f"morok:inbox:channel:{pubkey_hex}"
    try:
        await pubsub.subscribe(channel_name)
    except Exception as e:
        logger.exception("Subscribe failed: %s", e)
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        await release_ws_slot(redis, pubkey_hex, connection_id)
        return

    # 4. Run two cooperating tasks:
    #    - reader: forward pub/sub notifications to the client
    #    - writer: receive client messages (ack, pong)
    #    - pinger: send periodic ping

    async def reader_task() -> None:
        """Listen to Redis pub/sub and forward to client.

        Events come in two formats:
        - JSON: {"kind": "new"|"deleted"|"read", ...}
        - Legacy bare envelope_id string (treated as "new")
        """
        try:
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                raw = message["data"]
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")

                # Try JSON event first
                event = None
                if raw and raw[:1] == "{":
                    try:
                        event = json.loads(raw)
                    except json.JSONDecodeError:
                        event = None

                if event and isinstance(event, dict) and "kind" in event:
                    kind = event["kind"]
                    if kind == "new":
                        envelope_id = event.get("envelope_id")
                        if not envelope_id:
                            continue
                        # Direct meta lookup. The old list_inbox(limit=200)
                        # scan silently dropped "new" events whenever the
                        # inbox held >200 pending envelopes (the fresh one
                        # sorts past the cutoff). The pub/sub channel is
                        # already scoped to THIS recipient, so the meta is
                        # ours by construction; meta=None just means it
                        # expired/was deleted between publish and read.
                        env = await get_envelope_meta(redis, envelope_id)
                        if env is not None:
                            await websocket.send_json({"type": "new", "envelope": env})
                    elif kind == "deleted":
                        await websocket.send_json({
                            "type": "deleted",
                            "envelope_id": event.get("envelope_id"),
                            "by": event.get("by"),
                            "group_id": event.get("group_id"),
                        })
                    elif kind == "read":
                        await websocket.send_json({
                            "type": "read",
                            "envelope_id": event.get("envelope_id"),
                            "reader": event.get("reader"),
                            "group_id": event.get("group_id"),
                        })
                    elif kind == "group_gone":
                        await websocket.send_json({
                            "type": "group_gone",
                            "group_id": event.get("group_id"),
                            "by": event.get("by"),
                        })
                    elif kind == "session_revoked":
                        # Сесію відкликано (logout, logout-everywhere,
                        # видалення акаунта). Токен перевірявся лише під
                        # час handshake, тож без цієї гілки сокет жив би
                        # далі й приймав ack — вкрадений токен переживав
                        # би «вийти з усіх пристроїв».
                        #
                        # token_hash=None → закрити всі сокети власника.
                        # Інакше — лише той, чий токен збігається, щоб
                        # звичайний logout не рвав інші пристрої.
                        th = event.get("token_hash")
                        if th is not None and th != _my_token_hash:
                            continue
                        logger.info(
                            "inbox WS: session revoked for %s, closing",
                            pubkey_hex[:8],
                        )
                        # 4001 — той самий код, що й «немає токена»:
                        # клієнт трактує його як auth-fail і піде
                        # логінитись наново. Власник із seed'ом мовчки
                        # перепідключиться, а зловмисник, у якого лише
                        # токен, — ні.
                        with contextlib.suppress(Exception):
                            await websocket.close(code=4001, reason="session_revoked")
                        return
                    else:
                        logger.warning("inbox WS: unknown event kind %s", kind)
                    continue

                # Legacy fallback: bare envelope_id
                envelope_id = raw
                env = await get_envelope_meta(redis, envelope_id)
                if env is not None:
                    await websocket.send_json({"type": "new", "envelope": env})
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.exception("Reader failed: %s", e)

    async def writer_task() -> None:
        """Read incoming client frames (acks, pongs)."""
        try:
            while True:
                raw = await websocket.receive_text()
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    await websocket.send_json({
                        "type": "error",
                        "detail": "invalid_json",
                    })
                    continue

                msg_type = msg.get("type")
                if msg_type == "ack":
                    envelope_id = msg.get("envelope_id")
                    if envelope_id:
                        await acknowledge_envelope(
                            redis, pubkey_hex, envelope_id
                        )
                elif msg_type == "pong":
                    pass  # heartbeat received, all good
                else:
                    await websocket.send_json({
                        "type": "error",
                        "detail": f"unknown_message_type: {msg_type}",
                    })
        except WebSocketDisconnect:
            raise
        except asyncio.CancelledError:
            raise

    async def pinger_task() -> None:
        """Periodic ping to detect stale connections."""
        try:
            while True:
                await asyncio.sleep(PING_INTERVAL_SECONDS)
                await websocket.send_json({"type": "ping"})
                # Живе з'єднання => тримаємо лічильник онлайну живим...
                try:
                    await redis.expire(ws_active_key, 90)
                except Exception:
                    pass
                # ...і оновлюємо час життя WS-слота, щоб його не вважали
                # мертвим і не викинули при reserve інших з'єднань.
                try:
                    await refresh_ws_slot(redis, pubkey_hex, connection_id)
                except Exception:
                    pass
        except asyncio.CancelledError:
            raise

    # Run all three in parallel; if any finishes (or errors), tear down.
    tasks = [
        asyncio.create_task(reader_task()),
        asyncio.create_task(writer_task()),
        asyncio.create_task(pinger_task()),
    ]
    try:
        done, pending = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED
        )
    except WebSocketDisconnect:
        logger.info("inbox WS disconnect: pubkey=%s...", pubkey_hex[:8])
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        # Wait for cancellations to settle
        await asyncio.gather(*tasks, return_exceptions=True)
        try:
            await pubsub.unsubscribe(channel_name)
            await pubsub.aclose()
        except Exception:
            pass
        try:
            await websocket.close()
        except Exception:
            pass
        # Decrement WS-active counter; once it hits 0 the key is gone and
        # push fanout will start sending notifications for this user again.
        try:
            new_count = await redis.decr(ws_active_key)
            if new_count is not None and new_count <= 0:
                await redis.delete(ws_active_key)
        except Exception as e:
            logger.warning("ws-active decr failed for %s: %s", pubkey_hex[:8], e)
        # Free the concurrent-connection slot reserved at handshake.
        await release_ws_slot(redis, pubkey_hex, connection_id)
        logger.info("inbox WS closed: pubkey=%s...", pubkey_hex[:8])
