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


_OWNER_KEY_PREFIX = "morok:burner_owner:"


def _owner_key(pubkey_hex: str) -> str:
    return f"{_OWNER_KEY_PREFIX}{pubkey_hex}"


def generate_token() -> str:
    """24-char URL-safe base64 (~18 bytes of randomness)."""
    return secrets.token_urlsafe(18)


# Атомарний check-then-insert для per-owner ліміту активних токенів
# (жорсткий свіжий прохід — той самий клас race, що ми вже закривали
# для inbox depth/group capacity/DMS quota: count_active_tokens() і
# create_token() були ОКРЕМИМИ операціями, N паралельних POST /burner
# могли всі побачити active=9<10 і всі створити токен).
#
# Складніше за звичайний EVAL-guard: наявна (стара, неатомарна) логіка
# ТЕЖ чистить stale-членів SET перед підрахунком (list_tokens_for_owner
# робить lazy cleanup) — просте SCARD без цього кроку дало б false
# positives (власник із протухлими, але ще не вичищеними токенами
# отримав би несправедливу відмову). Тому Lua-скрипт сам ітерує SET,
# видаляє мертві записи (EXISTS перевірка кожного) і рахує РЕАЛЬНО
# живих — в одному атомарному проході.
_CREATE_LUA = """
local owner_key = KEYS[1]
local token_key = KEYS[2]
local max_active = tonumber(ARGV[1])
local token = ARGV[2]
local payload = ARGV[3]
local ttl = tonumber(ARGV[4])
local token_prefix = ARGV[5]

local members = redis.call('SMEMBERS', owner_key)
local alive = 0
for i, member in ipairs(members) do
    if redis.call('EXISTS', token_prefix .. member) == 1 then
        alive = alive + 1
    else
        redis.call('SREM', owner_key, member)
    end
end

if alive >= max_active then
    return {0, alive}
end

redis.call('SET', token_key, payload, 'EX', ttl)
redis.call('SADD', owner_key, token)
return {1, alive + 1}
"""


async def create_token(
    redis: redis_async.Redis,
    owner_pubkey_hex: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    label: str | None = None,
) -> dict | None:
    """
    Create a new burner token. Returns the same shape as get_token, or
    None if the owner is already at MAX_ACTIVE_TOKENS_PER_OWNER (caller
    must check for None — the old "count first, then create" pattern
    let this be checked separately and non-atomically; now the limit is
    enforced INSIDE the same atomic operation as the insert).

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

    result = await redis.eval(
        _CREATE_LUA,
        2,
        _owner_key(owner_pubkey_hex),
        _token_key(token),
        str(MAX_ACTIVE_TOKENS_PER_OWNER),
        token,
        payload,
        str(ttl),
        _token_key(""),  # префікс: _token_key("") -> "morok:burner_token:"
    )
    allowed = bool(result[0])
    if not allowed:
        return None

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


# Атомарний інкремент лічильника повідомлень.
#
# ЧОМУ LUA. Стара реалізація робила GET → decode → +1 → SET: дві паралельні
# відправки читали 99 і обидві писали 100 (обхід ліміту), а гонка з revoke
# могла «воскресити» токен — потік A прочитав metadata, потік B видалив
# ключ (revoke), потік A записав metadata назад. Lua виконується в Redis
# як одна неподільна операція, тож обидві гонки зникають: revoke або
# відбувся ДО (GET поверне nil → відмова), або ПІСЛЯ (перемагає revoke).
#
# Ключ власника (SREM при auto-revoke) будується всередині скрипта з
# meta.owner_pubkey — це нормально для одиночного Redis; для Redis Cluster
# довелося б передавати його через KEYS[2] (у нас кластера немає).
_INCR_LUA = """
local raw = redis.call('GET', KEYS[1])
if not raw then
    return {0, 0}
end
local ok, meta = pcall(cjson.decode, raw)
if not ok then
    return {0, 0}
end
local count = (tonumber(meta['message_count']) or 0) + 1
if count > tonumber(ARGV[1]) then
    -- Auto-revoke: ліміт вичерпано, токен знищується атомарно.
    redis.call('DEL', KEYS[1])
    if meta['owner_pubkey'] then
        redis.call('SREM', ARGV[3] .. meta['owner_pubkey'], ARGV[2])
    end
    return {0, count}
end
meta['message_count'] = count
-- KEEPTTL: зберігаємо залишок життя токена (Redis >= 6.0).
redis.call('SET', KEYS[1], cjson.encode(meta), 'KEEPTTL')
return {1, count}
"""


async def increment_message_count(
    redis: redis_async.Redis, token: str,
) -> tuple[bool, int]:
    """
    Atomically increment message count for a token (single Lua script).

    Returns (allowed, new_count). If new_count exceeds MAX_MESSAGES_PER_TOKEN
    the token is auto-revoked inside the same atomic operation and we return
    (False, count) — the message must NOT be delivered.
    """
    result = await redis.eval(
        _INCR_LUA,
        1,
        _token_key(token),
        str(MAX_MESSAGES_PER_TOKEN),
        token,
        _OWNER_KEY_PREFIX,
    )
    allowed, count = int(result[0]), int(result[1])
    return bool(allowed), count


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
