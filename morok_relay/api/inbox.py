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
import json
import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from ..deps import get_redis
from ..queue import acknowledge_envelope, list_inbox
from ..sessions import verify_session_token

logger = logging.getLogger(__name__)

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
    session = await verify_session_token(redis, token)
    if session is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    pubkey_hex = session.pubkey_hex
    await websocket.accept()
    logger.info("inbox WebSocket open: pubkey=%s...", pubkey_hex[:8])

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
        return

    # 3. Subscribe to pub/sub channel for this recipient
    pubsub = redis.pubsub()
    channel_name = f"morok:inbox:channel:{pubkey_hex}"
    try:
        await pubsub.subscribe(channel_name)
    except Exception as e:
        logger.exception("Subscribe failed: %s", e)
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        return

    # 4. Run two cooperating tasks:
    #    - reader: forward pub/sub notifications to the client
    #    - writer: receive client messages (ack, pong)
    #    - pinger: send periodic ping

    async def reader_task() -> None:
        """Listen to Redis pub/sub and forward to client."""
        try:
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                envelope_id = message["data"].decode("utf-8")
                # Look up the metadata
                envs = await list_inbox(redis, pubkey_hex, limit=200)
                env = next(
                    (e for e in envs if e["envelope_id"] == envelope_id), None
                )
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
        logger.info("inbox WS closed: pubkey=%s...", pubkey_hex[:8])
