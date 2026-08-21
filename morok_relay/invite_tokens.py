"""
Group invite tokens — Redis-backed, one-time-use.

Tokens are short URL-safe strings (~24 chars) that grant the bearer the
right to join a specific group exactly once.

Flow:
    1. Admin creates a token via POST /api/v1/groups/{id}/invites
       → token + expires_at returned to admin
       → admin shares the join URL (https://relay/web/#join?t=<token>)
    2. Recipient opens the URL, becomes authenticated, then calls
       POST /api/v1/groups/join?token=<...>
    3. Server validates token, adds the caller as a member, deletes
       the token (consumed).

Tokens are tied to a single group_id and to a single creator_pubkey
(the admin who created them) — both stored as metadata so we can audit.

Keys
----
    morok:invite_token:{token}    — JSON {group_id, created_by, created_at, ttl}
                                    Redis TTL = remaining lifetime
    morok:group_invites:{group_id} — SET of token strings (to enumerate)
"""
from __future__ import annotations

import json
import secrets
import time

import redis.asyncio as redis_async

# Minimum / maximum lifetime caps for invite tokens
MIN_TTL_SECONDS = 60 * 60                  # 1 hour
MAX_TTL_SECONDS = 30 * 86400               # 30 days
DEFAULT_TTL_SECONDS = 7 * 86400            # 7 days

# Active tokens per admin per group (sanity ceiling)
MAX_ACTIVE_TOKENS_PER_GROUP = 20


def _token_key(token: str) -> str:
    return f"morok:invite_token:{token}"


def _group_invites_key(group_id: str) -> str:
    return f"morok:group_invites:{group_id}"


def generate_token() -> str:
    """24-char URL-safe base64 (~18 bytes of randomness)."""
    return secrets.token_urlsafe(18)


# Атомарний check-then-insert (жорсткий свіжий прохід — той самий клас
# race, тим самим часом виявлений і закритий у burner_tokens.py:
# count_active_tokens() і create_token() були окремими операціями, N
# паралельних POST /invites могли всі побачити active<MAX і всі пройти).
# Складніше за звичайний EVAL-guard: наявна логіка (list_tokens) ТЕЖ
# чистить stale-членів SET перед підрахунком — простий SCARD без цього
# кроку дав би false positives (адмін із протухлими, ще не вичищеними
# токенами отримав би несправедливу відмову). Лічимо реально живих
# в одному атомарному проході.
_CREATE_LUA = """
local group_key = KEYS[1]
local token_key = KEYS[2]
local max_active = tonumber(ARGV[1])
local token = ARGV[2]
local payload = ARGV[3]
local ttl = tonumber(ARGV[4])
local set_ttl = tonumber(ARGV[5])
local token_prefix = ARGV[6]

local members = redis.call('SMEMBERS', group_key)
local alive = 0
for i, member in ipairs(members) do
    if redis.call('EXISTS', token_prefix .. member) == 1 then
        alive = alive + 1
    else
        redis.call('SREM', group_key, member)
    end
end

if alive >= max_active then
    return {0, alive}
end

redis.call('SET', token_key, payload, 'EX', ttl)
redis.call('SADD', group_key, token)
redis.call('EXPIRE', group_key, set_ttl)
return {1, alive + 1}
"""


async def create_token(
    redis: redis_async.Redis,
    group_id: str,
    created_by_pubkey_hex: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> dict | None:
    """
    Create a new invite token. Returns {token, expires_at, created_at},
    or None if the group is already at MAX_ACTIVE_TOKENS_PER_GROUP
    (limit enforced ATOMICALLY inside the same operation as the insert
    — caller must check for None).

    Caps ttl_seconds to MIN_TTL_SECONDS / MAX_TTL_SECONDS.
    """
    ttl = max(MIN_TTL_SECONDS, min(ttl_seconds, MAX_TTL_SECONDS))
    now = int(time.time())
    expires_at = now + ttl
    token = generate_token()

    payload = json.dumps({
        "group_id": group_id,
        "created_by": created_by_pubkey_hex,
        "created_at": now,
        "expires_at": expires_at,
    })

    result = await redis.eval(
        _CREATE_LUA,
        2,
        _group_invites_key(group_id),
        _token_key(token),
        str(MAX_ACTIVE_TOKENS_PER_GROUP),
        token,
        payload,
        str(ttl),
        str(MAX_TTL_SECONDS + 86400),
        _token_key(""),  # префікс: _token_key("") -> "morok:invite_token:"
    )
    allowed = bool(result[0])
    if not allowed:
        return None

    return {
        "token": token,
        "expires_at": expires_at,
        "created_at": now,
    }


async def get_token(redis: redis_async.Redis, token: str) -> dict | None:
    """Return the metadata for a token, or None if it doesn't exist / expired."""
    raw = await redis.get(_token_key(token))
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


async def consume_token(redis: redis_async.Redis, token: str) -> dict | None:
    """
    Atomically read + delete a token. Returns metadata if valid, else None.

    Uses Redis GETDEL (since 6.2) so that if two clients race to consume
    the same invite link, exactly one observes the metadata and the other
    sees None — without it the previous "GET then DELETE" left a window
    where both could pass the check.

    The set-side cleanup (group_invites:<gid>) is still a separate hop;
    it's an enumeration aid, not a security gate, so a brief stale entry
    there is harmless (list_tokens already does lazy cleanup).
    """
    raw = await redis.execute_command("GETDEL", _token_key(token))
    if raw is None:
        return None
    try:
        meta = json.loads(raw)
    except json.JSONDecodeError:
        return None
    group_id = meta.get("group_id")
    if group_id:
        try:
            await redis.srem(_group_invites_key(group_id), token)
        except Exception:
            # Set-side cleanup is best-effort — list_tokens will catch up.
            pass
    return meta


async def revoke_token(redis: redis_async.Redis, group_id: str, token: str) -> bool:
    """Manually revoke a token. Returns True if it existed."""
    async with redis.pipeline(transaction=True) as pipe:
        pipe.delete(_token_key(token))
        pipe.srem(_group_invites_key(group_id), token)
        results = await pipe.execute()
    return bool(results[0])


async def list_tokens(redis: redis_async.Redis, group_id: str) -> list[dict]:
    """
    List all currently-active tokens for a group. Each returned dict has
    {token, expires_at, created_at, created_by}.

    Cleans up the SET as a side effect — removes stale members whose key
    has already expired.
    """
    members = await redis.smembers(_group_invites_key(group_id))
    if not members:
        return []
    decoded = [m.decode("utf-8") if isinstance(m, bytes) else m for m in members]

    out = []
    stale = []
    async with redis.pipeline(transaction=False) as pipe:
        for t in decoded:
            pipe.get(_token_key(t))
        raw_list = await pipe.execute()

    for t, raw in zip(decoded, raw_list, strict=False):
        if raw is None:
            stale.append(t)
            continue
        try:
            meta = json.loads(raw)
            out.append({
                "token": t,
                "group_id": meta.get("group_id"),
                "created_by": meta.get("created_by"),
                "created_at": meta.get("created_at"),
                "expires_at": meta.get("expires_at"),
            })
        except json.JSONDecodeError:
            stale.append(t)

    # Lazy cleanup of stale members
    if stale:
        try:
            await redis.srem(_group_invites_key(group_id), *stale)
        except Exception:
            pass

    return out


async def count_active_tokens(redis: redis_async.Redis, group_id: str) -> int:
    """Number of currently-active tokens for a group (after cleanup)."""
    tokens = await list_tokens(redis, group_id)
    return len(tokens)
