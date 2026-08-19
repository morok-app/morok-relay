"""
Redis-based rate limiting for FastAPI endpoints.

Design
------
Simple per-minute bucket counter in Redis. Each (bucket, identifier) pair
gets a key like `morok:ratelimit:auth:1.2.3.4:1747838460` where the suffix
is the current minute (epoch // 60). INCR + EXPIRE 60s.

If the count exceeds the configured limit, we return 429 with a
Retry-After header pointing at the next minute boundary.

This is a fixed-window counter (not sliding). A burst right at the
boundary CAN get 2x the limit (15:59:59 + 16:00:00). Acceptable for
our threat model — we're stopping spam, not enforcing financial QoS.

Identifiers
-----------
- For unauthenticated endpoints: IP address (from X-Real-IP header set
  by nginx, fallback to request.client.host).
- For authenticated endpoints: pubkey_hex (from session).

Disable
-------
Set `RATE_LIMIT_ENABLED=false` in .env to disable entirely (e.g. for
running the test client locally without hitting limits).

Поведінка при збої Redis (аудит 4, MEDIUM-2)
--------------------------------------------
Раніше ВСІ бакети при недоступності Redis робили fail-open. Для спаму це
прийнятно, але означало: хто завалить або пригальмує Redis, той
одночасно знімає ліміти з автентифікації — тобто відкриває вільний
перебір на /auth/verify і /admin/login. Гірше, це підсилює саме себе:
навантаження → Redis гальмує → ліміти зникають → ще більше навантаження.

Тепер бакети розділені за критичністю (CRITICAL_BUCKETS). Для критичних
при збої Redis вмикається ЛОКАЛЬНИЙ in-process лічильник (див.
_LocalFallbackLimiter): він не такий точний (у кожного воркера свій, тож
фактичний ліміт множиться на кількість воркерів), але перетворює
«лімітів немає взагалі» на «ліміт у кілька разів слабший» — різниця між
вільним перебором і сповільненим. Некритичні бакети лишаються fail-open,
щоб блимок Redis не ламав доставку повідомлень.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from redis.asyncio import Redis

from .config import get_settings
from .db import get_redis

logger = logging.getLogger(__name__)


# ============================================================================
# Fail-mode policy
# ============================================================================

# Бакети, де fail-open = відкритий перебір облікових даних або
# безкоштовне засмічення таблиць. Для них при збої Redis працює
# локальний резерв замість «пропускати все».
CRITICAL_BUCKETS = frozenset({
    "auth_challenge",
    "auth_verify",
    "admin_login",
    "federation_handshake",
    # Публічний restore-ендпоінт віддає ЗАШИФРОВАНИЙ SEED за самим лише
    # username (авторизації немає за задумом — людина відновлюється на
    # новому пристрої). Єдиний захист від масового викачування блобів
    # під offline-перебір PIN'а — ліміт 3/хв. Fail-open тут означав би:
    # поки Redis лежить, качай бекапи всієї бази без обмежень.
    "backup_restore",
})


class _LocalFallbackLimiter:
    """
    Аварійний лічильник у пам'яті процесу на випадок недоступності Redis.

    НАВМИСНІ ОБМЕЖЕННЯ. Стан не спільний між воркерами (кожен має свій
    словник), тож реальний ліміт множиться на кількість воркерів; після
    рестарту процесу лічильники обнуляються. Це не заміна Redis, а
    аварійний резерв: мета — не пропустити тисячі спроб перебору, поки
    Redis лежить, а не забезпечити точний QoS.

    Пам'ять обмежена: вікно живе одну хвилину, старі вікна викидаються
    при кожному новому, тож словник не росте нескінченно навіть під
    атакою з багатьох IP.
    """

    __slots__ = ("_counts", "_window")

    def __init__(self) -> None:
        self._counts: dict[tuple[str, str], int] = defaultdict(int)
        self._window: int = 0

    def hit(self, bucket: str, identifier: str, limit: int) -> tuple[bool, int]:
        window = int(time.time()) // 60
        if window != self._window:
            self._counts.clear()
            self._window = window
        key = (bucket, identifier)
        self._counts[key] += 1
        count = self._counts[key]
        return count <= limit, count


_local_fallback = _LocalFallbackLimiter()


# ============================================================================
# Identifier extraction
# ============================================================================

def get_ip_from_request(request: Request) -> str:
    """
    Extract the client's IP — SECURELY.

    Forwarded headers (X-Real-IP, X-Forwarded-For) are only trusted when
    the DIRECT connection comes from a configured trusted proxy (nginx on
    loopback by default). Any other source has its forwarded headers
    ignored, falling back to the real peer address.

    This closes a spoofing hole: without the trust check, anyone reaching
    uvicorn directly (e.g. if the port is exposed past nginx) could set
    X-Real-IP to an arbitrary value to bypass per-IP rate-limits (auth,
    admin login, sealed) and poison login_log.ip_hash.
    """
    peer = request.client.host if request.client else None

    # Is the immediate connection from a trusted proxy?
    settings = get_settings()
    trusted = {
        ip.strip() for ip in (settings.trusted_proxy_ips or "").split(",")
        if ip.strip()
    }
    proxy_trusted = peer is not None and peer in trusted

    if proxy_trusted:
        # Onion-трафік: nginx (окремий listener для Tor) ставить
        # X-Morok-Via: tor. Клієнтський заголовок з такою назвою
        # затирається в обох напрямках, тож підробити його не можна.
        #
        # У Tor-клієнтів немає осмисленої IP-адреси з нашого боку — усі
        # приходять із loopback. Тому на РІВНІ ідентифікатора вони
        # ділять один рядок "tor". Це не залишає їх зі спільним лімітом
        # у прод-поведінці: rate_limit_tor_aware_by_* (нижче в цьому
        # файлі) розпізнає identifier=="tor" і застосовує підвищену
        # глобальну стелю + per-claimed-identity sub-limit саме тому,
        # що інакше один Tor-клієнт міг би вичерпати ліміт для всіх.
        # Ендпоінти, що досі використовують голий rate_limit_by_ip
        # (без tor-aware обгортки), спільний бакет "tor" МАЮТЬ —
        # свідомо, бо для них поки не було потреби в per-identity шарі.
        if (request.headers.get("x-morok-via") or "").strip().lower() == "tor":
            return "tor"

        # nginx sets X-Real-IP $remote_addr — reliable here.
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
        # Fallback to leftmost XFF entry if X-Real-IP absent.
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()

    # Untrusted (or direct) connection: NEVER trust forwarded headers.
    if peer:
        return peer

    return "unknown"


# ============================================================================
# Core check
# ============================================================================

async def check_rate_limit(
    redis: Redis,
    bucket: str,
    identifier: str,
    limit_per_minute: int,
) -> tuple[bool, int, int]:
    """
    Check and increment a rate-limit counter.

    Returns: (allowed, current_count, retry_after_seconds)
    - allowed: True if request is within limit
    - current_count: how many requests in this minute window
    - retry_after_seconds: how many seconds until window resets

    Bucket = logical name like "auth", "messages", "groups_create".
    Identifier = IP or pubkey_hex.
    """
    settings = get_settings()
    if not settings.rate_limit_enabled:
        return True, 0, 0

    now = int(time.time())
    minute_window = now // 60
    retry_after = 60 - (now % 60)

    key = f"morok:ratelimit:{bucket}:{identifier}:{minute_window}"

    try:
        async with redis.pipeline(transaction=False) as pipe:
            pipe.incr(key)
            pipe.expire(key, 90)  # 90s > 60s to outlive the window safely
            results = await pipe.execute()
        count = results[0]
    except Exception as e:
        # Redis недоступний. Поведінка залежить від критичності бакета.
        if bucket in CRITICAL_BUCKETS:
            allowed, count = _local_fallback.hit(bucket, identifier, limit_per_minute)
            # ERROR, а не WARNING: це стан, який має бути видно в
            # моніторингу — ліміти зараз працюють гірше, ніж заявлено.
            logger.error(
                "Rate limit Redis failure on CRITICAL bucket %s — "
                "using in-process fallback (allowed=%s, count=%d): %s",
                bucket, allowed, count, e,
            )
            return allowed, count, retry_after
        logger.warning("Rate limit check failed (failing open): %s", e)
        return True, 0, 0

    allowed = count <= limit_per_minute
    return allowed, count, retry_after


def _raise_rate_limited(retry_after: int, bucket: str, current: int, limit: int):
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"rate_limited_{bucket}_{current}_of_{limit}_per_minute",
        headers={"Retry-After": str(retry_after)},
    )


# ============================================================================
# FastAPI dependency factory
# ============================================================================

# ============================================================================
# Tor-aware rate limiting (аудит зовн. №3, HIGH)
# ============================================================================
#
# ПРОБЛЕМА. Усі onion-клієнти ділять один ідентифікатор "tor" (див.
# get_ip_from_request) — навмисно, бо в них немає осмисленої IP-адреси
# з нашого боку. Наслідок: ОДИН зловмисний Tor-клієнт міг вичерпати
# auth_challenge/auth_verify/backup_restore для ВСІХ Tor-користувачів
# одразу — доступ через onion практично зупинявся до нового вікна.
#
# РІШЕННЯ — два незалежні шари, не один:
#
#   1. Підвищена ГЛОБАЛЬНА стеля для бакету "tor" (× TOR_GLOBAL_
#      MULTIPLIER). Захищає сам relay від навантаження, дозволяючи
#      пропорційно більше — бо "tor" це не один клієнт, а весь
#      onion-трафік разом.
#
#   2. М'ЯКШИЙ SUB-LIMIT на "заявлений ідентифікатор" (pubkey з тіла
#      запиту для auth, username зі шляху для lookup/restore) — щоб
#      один клієнт не міг забрати весь глобальний пул одним заявленим
#      ідентифікатором.
#
# ЧОМУ НЕ ПРОСТО "прив'язати до pubkey" (як міг би виглядати наївний
# фікс). Заявлений pubkey на цій стадії НЕ верифікований — переходити
# на нього як на ЄДИНИЙ ідентифікатор відкриває targeted DoS: знаючи
# чийсь pubkey (публічний lookup його видає), зловмисник міг би через
# Tor спамити САМЕ під цей pubkey і заблокувати конкретну жертву від
# входу. Тому pubkey-шар — ДОДАТКОВИЙ до глобальної стелі, не заміна
# їй, а жертва завжди має фолбек через clearnet (де ліміт per-IP, не
# per-identity).
TOR_GLOBAL_MULTIPLIER = 20


async def _tor_aware_check(
    request: Request,
    redis,
    bucket: str,
    limit_per_minute: int,
    *,
    claimed_identity: str | None,
) -> tuple[bool, int, int]:
    """
    Обгортка над check_rate_limit: для звичайного трафіку — без змін
    (той самий виклик, що й завжди). Для Tor — обидва шари; повертає
    результат СУВОРІШОЇ з двох перевірок (перша, що впаде).
    """
    ip = get_ip_from_request(request)
    if ip != "tor":
        return await check_rate_limit(redis, bucket, ip, limit_per_minute)

    allowed, count, retry_after = await check_rate_limit(
        redis, bucket, "tor", limit_per_minute * TOR_GLOBAL_MULTIPLIER,
    )
    if not allowed:
        return allowed, count, retry_after

    if claimed_identity:
        return await check_rate_limit(
            redis, bucket, f"tor:{claimed_identity}", limit_per_minute,
        )
    return allowed, count, retry_after


def rate_limit_tor_aware_by_body_pubkey(bucket: str, limit_per_minute: int):
    """
    Для pre-auth ендпоінтів (auth/challenge, auth/verify), де заявлений
    pubkey_hex лежить у JSON-тілі запиту. Starlette кешує сире тіло,
    тож повторне read() тут не заважає подальшому Pydantic-парсингу
    того самого тіла в самому ендпоінті.
    """
    async def _dep(
        request: Request,
        redis: Annotated[Redis, Depends(get_redis)],
    ) -> None:
        claimed = None
        try:
            payload = await request.json()
            candidate = payload.get("pubkey_hex")
            if isinstance(candidate, str) and len(candidate) == 64:
                claimed = candidate.lower()
        except Exception:
            pass  # немає валідного JSON/поля — працює лише глобальна стеля

        allowed, count, retry_after = await _tor_aware_check(
            request, redis, bucket, limit_per_minute,
            claimed_identity=claimed,
        )
        if not allowed:
            logger.info(
                "Rate-limited (tor-aware) on bucket=%s (%d/min, limit=%d)",
                bucket, count, limit_per_minute,
            )
            _raise_rate_limited(retry_after, bucket, count, limit_per_minute)
    return _dep


def rate_limit_tor_aware_by_path_param(
    bucket: str, limit_per_minute: int, param_name: str,
):
    """Те саме, але ідентичність — параметр шляху (username у restore/
    lookup), а не поле JSON-тіла."""
    async def _dep(
        request: Request,
        redis: Annotated[Redis, Depends(get_redis)],
    ) -> None:
        claimed = request.path_params.get(param_name)
        if isinstance(claimed, str):
            claimed = claimed.lower()[:64]  # той самий здоровий глузд, що auth
        else:
            claimed = None

        allowed, count, retry_after = await _tor_aware_check(
            request, redis, bucket, limit_per_minute,
            claimed_identity=claimed,
        )
        if not allowed:
            logger.info(
                "Rate-limited (tor-aware) on bucket=%s (%d/min, limit=%d)",
                bucket, count, limit_per_minute,
            )
            _raise_rate_limited(retry_after, bucket, count, limit_per_minute)
    return _dep


def rate_limit_by_ip(bucket: str, limit_per_minute: int):
    """
    Dependency factory for IP-based rate limiting (unauthenticated endpoints).

    Usage:
        @router.post("/challenge", dependencies=[Depends(rate_limit_by_ip("auth", 10))])
        async def challenge(...): ...
    """
    async def _dep(
        request: Request,
        redis: Annotated[Redis, Depends(get_redis)],
    ) -> None:
        ip = get_ip_from_request(request)
        allowed, count, retry_after = await check_rate_limit(
            redis, bucket, ip, limit_per_minute,
        )
        if not allowed:
            logger.info(
                "Rate-limited IP %s on bucket=%s (%d/min, limit=%d)",
                ip, bucket, count, limit_per_minute,
            )
            _raise_rate_limited(retry_after, bucket, count, limit_per_minute)
    return _dep


def rate_limit_by_pubkey(bucket: str, limit_per_minute: int):
    """
    Dependency factory for pubkey-based rate limiting (authenticated endpoints).

    Requires the endpoint to also depend on CurrentSession.

    Usage:
        @router.post(
            "/messages",
            dependencies=[Depends(rate_limit_by_pubkey("messages", 60))],
        )
        async def send(current: CurrentSession, ...): ...
    """
    # Import here to avoid circular import at module load time.
    from .deps import get_current_session

    async def _dep(
        session = Depends(get_current_session),
        redis: Annotated[Redis, Depends(get_redis)] = None,
    ) -> None:
        allowed, count, retry_after = await check_rate_limit(
            redis, bucket, session.pubkey_hex, limit_per_minute,
        )
        if not allowed:
            logger.info(
                "Rate-limited pubkey %s on bucket=%s (%d/min, limit=%d)",
                session.pubkey_hex[:16], bucket, count, limit_per_minute,
            )
            _raise_rate_limited(retry_after, bucket, count, limit_per_minute)
    return _dep


# ============================================================================
# WebSocket helper — count concurrent connections per pubkey
# ============================================================================

# Key: morok:ws:connections:{pubkey_hex} → ZSET of {connection_id: last_seen_ts}
#
# Чому ZSET, а не SET: у SET кожен член живе доти, доки не зробиш srem.
# Якщо з'єднання вмирає аварійно (вбитий застосунок, обрив мережі) без
# чистого закриття — release_ws_slot не викликається, і "привид" висить
# у Redis до TTL усього ключа (раніше — 24 год!). Назбирається >limit
# привидів → reserve повертає False → relay віддає 403 ВСІМ з'єднанням
# цього pubkey, поки привиди не протухнуть. Саме це й сталося.
#
# ZSET зі score = час останньої активності лікує корінь: на кожному
# reserve ми спершу викидаємо членів, які не оновлювались довше за
# SLOT_TTL (мертві), і лише потім рахуємо. Живі з'єднання оновлюють свій
# score кожні 30с через refresh_ws_slot() у pinger'і, тож ніколи не
# випадають. Привиди фізично не накопичуються.

WS_SLOT_TTL_SECONDS = 90      # слот без оновлення довше за це = мертвий
WS_SLOT_KEY_TTL = 200         # TTL усього ключа (живі з'єднання його поновлюють)


def _ws_connections_key(pubkey_hex: str) -> str:
    return f"morok:ws:connections:{pubkey_hex}"


async def reserve_ws_slot(
    redis: Redis,
    pubkey_hex: str,
    connection_id: str,
    limit: int,
) -> bool:
    """
    Try to reserve a WebSocket connection slot for this pubkey.

    Returns True if reservation succeeded (caller can accept the connection),
    False if too many concurrent connections.

    On True, caller MUST call release_ws_slot() when the connection closes
    (in a finally block), and SHOULD call refresh_ws_slot() periodically
    (e.g. from the ping loop) to keep the slot alive.
    """
    settings = get_settings()
    if not settings.rate_limit_enabled:
        return True

    key = _ws_connections_key(pubkey_hex)
    now = time.time()
    cutoff = now - WS_SLOT_TTL_SECONDS
    try:
        async with redis.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(key, 0, cutoff)   # викинути мертві слоти
            pipe.zadd(key, {connection_id: now})    # додати/оновити свій
            pipe.expire(key, WS_SLOT_KEY_TTL)
            pipe.zcard(key)
            results = await pipe.execute()
        count = results[3]
    except Exception as e:
        logger.warning("WS slot reservation failed (failing open): %s", e)
        return True

    if count > limit:
        # Над лімітом — відкочуємо свій запис.
        try:
            await redis.zrem(key, connection_id)
        except Exception:
            pass
        return False
    return True


async def refresh_ws_slot(
    redis: Redis,
    pubkey_hex: str,
    connection_id: str,
) -> None:
    """Оновити час життя слота (виклик із pinger кожні ~30с)."""
    key = _ws_connections_key(pubkey_hex)
    try:
        async with redis.pipeline(transaction=True) as pipe:
            pipe.zadd(key, {connection_id: time.time()})
            pipe.expire(key, WS_SLOT_KEY_TTL)
            await pipe.execute()
    except Exception as e:
        logger.warning("WS slot refresh failed: %s", e)


async def release_ws_slot(
    redis: Redis,
    pubkey_hex: str,
    connection_id: str,
) -> None:
    """Release a WebSocket slot when the connection closes."""
    try:
        await redis.zrem(_ws_connections_key(pubkey_hex), connection_id)
    except Exception as e:
        logger.warning("WS slot release failed: %s", e)
