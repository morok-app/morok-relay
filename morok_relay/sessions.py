"""
Session token management.

Tokens are random 32-byte values, hex-encoded for transport.
Stored in Redis as:

    morok:session:{token_hex}  →  {pubkey_hex}
    TTL: 7 days, refreshed on each use (sliding window)

Also maintain a reverse lookup:

    morok:user_sessions:{pubkey_hex}  →  SET of {token_hex}

This lets us revoke all sessions for a user (logout-everywhere) without
scanning all tokens. The reverse index is best-effort — if a token expires
naturally, we clean up lazily on next user_sessions access.

Why not JWT?
- We want server-side revocation (panic/logout).
- We don't need offline verification — all auth happens against this relay.
- Redis is already in our stack.
- Tokens are short and opaque (32 bytes) instead of long JWT blobs.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass

import redis.asyncio as redis_async

logger = logging.getLogger(__name__)

SESSION_TTL_SECONDS = 7 * 24 * 60 * 60          # 7 days
SESSION_KEY_PREFIX = "morok:session:"
USER_SESSIONS_KEY_PREFIX = "morok:user_sessions:"


@dataclass(frozen=True, slots=True)
class Session:
    """A valid session — what `verify_session_token` returns."""
    token: str
    pubkey_hex: str
    expires_at: int


def _session_key(token: str) -> str:
    return f"{SESSION_KEY_PREFIX}{token}"


def _user_sessions_key(pubkey_hex: str) -> str:
    return f"{USER_SESSIONS_KEY_PREFIX}{pubkey_hex}"


def generate_token() -> str:
    """Generate a fresh session token (32 random bytes, hex-encoded)."""
    return secrets.token_hex(32)


async def create_session(redis: redis_async.Redis, pubkey_hex: str) -> Session:
    """
    Create a new session for a verified pubkey.

    Returns the Session including its raw token. The caller is responsible
    for sending the token back to the client over a secure channel.
    """
    token = generate_token()
    now = int(time.time())
    expires_at = now + SESSION_TTL_SECONDS

    # Store the session forward-lookup with TTL.
    await redis.setex(
        _session_key(token),
        SESSION_TTL_SECONDS,
        pubkey_hex.encode("utf-8"),
    )

    # Track in reverse index so we can revoke all sessions for a user.
    # The SET gets a TTL slightly longer than the session TTL and is
    # refreshed on each verify — so a naturally-expired session's token
    # doesn't linger in the index forever (it would otherwise accumulate
    # dead tokens and bloat Redis / slow revoke_all).
    await redis.sadd(_user_sessions_key(pubkey_hex), token.encode("utf-8"))
    await redis.expire(_user_sessions_key(pubkey_hex), SESSION_TTL_SECONDS + 86400)

    return Session(token=token, pubkey_hex=pubkey_hex, expires_at=expires_at)


async def verify_session_token(
    redis: redis_async.Redis, token: str
) -> Session | None:
    """
    Verify a session token and refresh its TTL (sliding window).

    Returns the Session if valid, None if expired/unknown.
    """
    if not token:
        return None

    key = _session_key(token)
    value = await redis.get(key)
    if value is None:
        return None

    pubkey_hex = value.decode("utf-8")

    # Sliding window: every use extends TTL by full 7 days from now.
    await redis.expire(key, SESSION_TTL_SECONDS)
    # Keep the reverse index alive alongside, so logout-everywhere stays
    # accurate and the SET doesn't expire out from under an active user.
    await redis.expire(
        _user_sessions_key(pubkey_hex), SESSION_TTL_SECONDS + 86400
    )

    expires_at = int(time.time()) + SESSION_TTL_SECONDS
    return Session(token=token, pubkey_hex=pubkey_hex, expires_at=expires_at)


async def revoke_session(redis: redis_async.Redis, token: str) -> bool:
    """
    Delete a single session token (logout from this device).

    Returns True if the token existed and was deleted.
    """
    key = _session_key(token)

    # Look up the pubkey first so we can clean the reverse index.
    value = await redis.get(key)
    if value is None:
        return False

    pubkey_hex = value.decode("utf-8")

    # Delete forward and reverse.
    deleted = await redis.delete(key)
    await redis.srem(_user_sessions_key(pubkey_hex), token.encode("utf-8"))

    # Розриваємо сокет САМЕ цієї сесії — інші пристрої користувача
    # лишаються підключеними (token задано, не None).
    await _publish_session_revoked(redis, pubkey_hex, token)

    return deleted > 0


async def _publish_session_revoked(
    redis: redis_async.Redis, pubkey_hex: str, token: str | None,
) -> None:
    """
    Сказати живим WebSocket'ам цього користувача, що сесію відкликано.

    ЧОМУ ЦЕ ПОТРІБНО. Токен перевіряється лише під час handshake — далі
    сокет живе сам по собі. Тобто видалення ключів із Redis закривало
    двері тільки для НОВИХ підключень, а вже відкрите з'єднання
    продовжувало приймати ack і видаляти конверти з інбокса.

    Сценарій, який це ламало: у зловмисника вкрадений токен і відкритий
    сокет → власник помічає і тисне «вийти з усіх пристроїв» → ключі в
    Redis знищено → чужий сокет живий і далі ack-ає нові повідомлення,
    через що справжній клієнт їх уже не отримує. Тобто revoke означав
    «нові підключення заборонені», а не «сесію знищено».

    token=None → закрити всі сокети користувача (logout-everywhere,
    видалення акаунта). token задано → закрити лише сокет цієї сесії,
    решту пристроїв не чіпати.

    Публікуємо в той самий канал, який WS уже слухає, — окрема
    інфраструктура не потрібна. Best-effort: якщо Redis саме зараз
    недоступний, ключі сесій усе одно видалені, тож новий handshake не
    пройде; гірший наслідок — сокет доживе до наступного ping/reconnect.
    """
    try:
        payload = json.dumps({
            "kind": "session_revoked",
            # Хеш, а не сам токен: канал слухають усі пристрої
            # користувача, і чужому токену там робити нічого.
            "token_hash": (
                hashlib.sha256(token.encode("utf-8")).hexdigest() if token else None
            ),
        })
        await redis.publish(f"morok:inbox:channel:{pubkey_hex}", payload)
    except Exception as e:  # noqa: BLE001 — best-effort, не валимо revoke
        logger.warning("session revoke publish failed for %s: %s", pubkey_hex[:8], e)


async def revoke_all_sessions(
    redis: redis_async.Redis, pubkey_hex: str
) -> int:
    """
    Delete all sessions for a user (panic-wipe / logout-everywhere).

    Returns the number of sessions revoked.
    """
    reverse_key = _user_sessions_key(pubkey_hex)
    tokens = await redis.smembers(reverse_key)
    if not tokens:
        # Живих сесій у Redis нема — але сокет міг лишитись відкритим із
        # ключем, що протух саме зараз. Сповіщаємо однаково.
        await _publish_session_revoked(redis, pubkey_hex, None)
        return 0

    # Build the list of forward-keys to delete.
    forward_keys = [_session_key(t.decode("utf-8")) for t in tokens]

    # Delete forward entries and the reverse set in one pipeline.
    async with redis.pipeline(transaction=False) as pipe:
        pipe.delete(*forward_keys)
        pipe.delete(reverse_key)
        results = await pipe.execute()

    # Ключі вже видалено — тепер розриваємо живі з'єднання.
    await _publish_session_revoked(redis, pubkey_hex, None)

    # results[0] is count of forward keys deleted
    return int(results[0])


# ============================================================================
# CHALLENGE STORAGE
# ============================================================================
# When the client requests a challenge, we store it briefly so that we can
# verify exactly-once usage (no replay) when they come back with a signature.

CHALLENGE_KEY_PREFIX = "morok:auth:challenge:"
CHALLENGE_TTL_SECONDS = 60


def _challenge_key(challenge_hex: str) -> str:
    return f"{CHALLENGE_KEY_PREFIX}{challenge_hex}"


async def store_challenge(
    redis: redis_async.Redis, challenge_hex: str, pubkey_hex: str
) -> None:
    """Remember that we issued this challenge to this pubkey."""
    await redis.setex(
        _challenge_key(challenge_hex),
        CHALLENGE_TTL_SECONDS,
        pubkey_hex.encode("utf-8"),
    )


async def consume_challenge(
    redis: redis_async.Redis, challenge_hex: str
) -> str | None:
    """
    Atomically: read the pubkey for which this challenge was issued, and
    delete the challenge so it can't be used twice.

    Returns the pubkey_hex if the challenge was valid, None otherwise.
    """
    # Pipeline to make GET+DEL atomic from our perspective.
    async with redis.pipeline(transaction=True) as pipe:
        pipe.get(_challenge_key(challenge_hex))
        pipe.delete(_challenge_key(challenge_hex))
        results = await pipe.execute()

    value = results[0]
    if value is None:
        return None
    return value.decode("utf-8")
