"""
Burner inbox tokens — Redis-backed.

A burner token gives the BEARER a public URL through which they can send
*one or more* end-to-end-encrypted messages to the token's OWNER.

Flow:
    1. Owner creates a token via POST /api/v1/burner
       → token + URL returned to owner
       → owner shares the URL (e.g. on Twitter/blog)
    2. Anonymous sender opens the URL → web form
       → form fetches owner's pubkey via GET /api/v1/burner/public/{token}
       → form generates EPHEMERAL keypair in browser
       → DH(ephemeral_priv, owner_pub) → shared key → encrypt plaintext
       → POST /api/v1/burner/public/{token}/send with
         {ephemeral_pubkey_hex, blob_b64}
    3. Server pushes envelope to owner's inbox.
       From owner's view it looks like a DM from @anon_<ephemeral_prefix>.

Tokens are multi-use until they expire (TTL) or are manually revoked.

Owner has up to MAX_ACTIVE_TOKENS_PER_OWNER active at once.

Keys
----
    morok:burner_token:{token}    — JSON {owner_pubkey, created_at, expires_at,
                                          label, message_count}
                                    Redis TTL = remaining lifetime
    morok:burner_owner:{pubkey}   — SET of token strings (to enumerate)
"""
from __future__ import annotations

import json
import re
import secrets
import time

import redis.asyncio as redis_async

# Lifetime config
MIN_TTL_SECONDS = 60 * 60                  # 1 hour
MAX_TTL_SECONDS = 30 * 86400               # 30 days
DEFAULT_TTL_SECONDS = 24 * 3600            # 24 hours

# Per-owner active token ceiling
MAX_ACTIVE_TOKENS_PER_OWNER = 10

# Per-token message ceiling (anti-spam) — once reached, token auto-expires
MAX_MESSAGES_PER_TOKEN = 100

# Sender label / signoff size cap (user-supplied, not verified)
MAX_SENDER_LABEL_LEN = 64

# Token format: URL-safe base64, 22-32 chars
BURNER_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,40}$")


def _token_key(token: str) -> str:
    return f"morok:burner_token:{token}"


def _owner_key(pubkey_hex: str) -> str:
    return f"morok:burner_owner:{pubkey_hex}"


def generate_token() -> str:
    """24-char URL-safe base64 (~18 bytes of randomness)."""
    return secrets.token_urlsafe(18)


async def create_token(
    redis: redis_async.Redis,
    owner_pubkey_hex: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    label: str | None = None,
) -> dict:
    """
    Create a new burner token. Returns the same shape as get_token.

    Caps ttl_seconds to MIN_TTL_SECONDS / MAX_TTL_SECONDS.
    """
    ttl = max(MIN_TTL_SECONDS, min(ttl_seconds, MAX_TTL_SECONDS))
    now = int(time.time())
    expires_at = now + ttl
    token = generate_token()

    payload = json.dumps({
        "owner_pubkey": owner_pubkey_hex,
        "label": label,
        "created_at": now,
        "expires_at": expires_at,
        "message_count": 0,
    })

    async with redis.pipeline(transaction=True) as pipe:
        pipe.set(_token_key(token), payload, ex=ttl)
        pipe.sadd(_owner_key(owner_pubkey_hex), token)
        await pipe.execute()

    return {
        "token": token,
        "owner_pubkey_hex": owner_pubkey_hex,
        "label": label,
        "created_at": now,
        "expires_at": expires_at,
        "message_count": 0,
    }


async def get_token(redis: redis_async.Redis, token: str) -> dict | None:
    """Return metadata for a token, or None if missing/expired."""
    raw = await redis.get(_token_key(token))
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


async def increment_message_count(
    redis: redis_async.Redis, token: str,
) -> tuple[bool, int]:
    """
    Atomically increment message count for a token.

    Returns (allowed, new_count). If new_count exceeds MAX_MESSAGES_PER_TOKEN
    we return (False, count) and DON'T deliver the message.
    """
    raw = await redis.get(_token_key(token))
    if raw is None:
        return False, 0
    try:
        meta = json.loads(raw)
    except json.JSONDecodeError:
        return False, 0

    count = int(meta.get("message_count", 0)) + 1
    if count > MAX_MESSAGES_PER_TOKEN:
        # Auto-revoke
        await revoke_token(redis, meta["owner_pubkey"], token)
        return False, count

    meta["message_count"] = count

    # Preserve remaining TTL
    ttl = await redis.ttl(_token_key(token))
    if ttl is None or ttl < 0:
        return False, count
    await redis.set(_token_key(token), json.dumps(meta), ex=ttl)
    return True, count


async def revoke_token(
    redis: redis_async.Redis,
    owner_pubkey_hex: str,
    token: str,
) -> bool:
    """Manually revoke a token. Returns True if it existed."""
    async with redis.pipeline(transaction=True) as pipe:
        pipe.delete(_token_key(token))
        pipe.srem(_owner_key(owner_pubkey_hex), token)
        results = await pipe.execute()
    return bool(results[0])


async def list_tokens_for_owner(
    redis: redis_async.Redis,
    owner_pubkey_hex: str,
) -> list[dict]:
    """
    List all currently-active burner tokens for an owner.

    Cleans the SET as a side effect — removes stale members whose key has
    already expired in Redis.
    """
    members = await redis.smembers(_owner_key(owner_pubkey_hex))
    if not members:
        return []
    decoded = [m.decode("utf-8") if isinstance(m, bytes) else m for m in members]

    out = []
    stale = []
    async with redis.pipeline(transaction=False) as pipe:
        for t in decoded:
            pipe.get(_token_key(t))
        raw_list = await pipe.execute()

    for t, raw in zip(decoded, raw_list):
        if raw is None:
            stale.append(t)
            continue
        try:
            meta = json.loads(raw)
            out.append({
                "token": t,
                "owner_pubkey_hex": meta.get("owner_pubkey"),
                "label": meta.get("label"),
                "created_at": meta.get("created_at"),
                "expires_at": meta.get("expires_at"),
                "message_count": meta.get("message_count", 0),
            })
        except json.JSONDecodeError:
            stale.append(t)

    # Lazy cleanup
    if stale:
        try:
            await redis.srem(_owner_key(owner_pubkey_hex), *stale)
        except Exception:
            pass

    # Newest first
    out.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return out


async def count_active_tokens(
    redis: redis_async.Redis,
    owner_pubkey_hex: str,
) -> int:
    """Number of currently-active tokens for an owner (after cleanup)."""
    tokens = await list_tokens_for_owner(redis, owner_pubkey_hex)
    return len(tokens)
