"""
Rate limit: поведінка при недоступності Redis (аудит 4, MEDIUM-2).

Знахідка: всі бакети робили fail-open. Отже, хто завалить або
пригальмує Redis, той одночасно знімає ліміт з автентифікації —
вільний перебір на /auth/verify і /admin/login. І це підсилює саме
себе: навантаження → Redis гальмує → ліміти зникають.

Фікс: критичні бакети (auth, admin_login, federation_handshake) при
збої Redis переходять на локальний in-process лічильник; решта
лишається fail-open, щоб блимок Redis не ламав доставку.
"""
from __future__ import annotations

import pytest

from morok_relay import rate_limit as rl

pytestmark = pytest.mark.asyncio


class _BrokenRedis:
    """Redis, що падає на будь-якій операції."""

    def pipeline(self, *a, **kw):
        raise ConnectionError("redis down")


@pytest.fixture(autouse=True)
def _fresh_fallback():
    """Кожен тест починає з чистим локальним лічильником."""
    rl._local_fallback._counts.clear()
    rl._local_fallback._window = 0
    yield
    rl._local_fallback._counts.clear()
    rl._local_fallback._window = 0


async def test_critical_bucket_still_limits_when_redis_down():
    """ГОЛОВНЕ: auth не стає безлімітним, коли Redis лежить."""
    broken = _BrokenRedis()
    limit = 5

    results = [
        (await rl.check_rate_limit(broken, "auth_verify", "1.2.3.4", limit))[0]
        for _ in range(limit + 5)
    ]
    assert results[:limit] == [True] * limit
    assert results[limit:] == [False] * 5, "перебір проходить попри ліміт"


async def test_noncritical_bucket_fails_open_when_redis_down():
    """Доставка повідомлень не має ламатись через блимок Redis."""
    broken = _BrokenRedis()
    for _ in range(50):
        allowed, _, _ = await rl.check_rate_limit(broken, "messages", "1.2.3.4", 5)
        assert allowed is True


async def test_fallback_is_per_identifier():
    """Вичерпаний ліміт одного IP не блокує інші."""
    broken = _BrokenRedis()
    for _ in range(6):
        await rl.check_rate_limit(broken, "auth_verify", "1.1.1.1", 5)

    allowed, _, _ = await rl.check_rate_limit(broken, "auth_verify", "1.1.1.1", 5)
    assert allowed is False
    allowed, _, _ = await rl.check_rate_limit(broken, "auth_verify", "2.2.2.2", 5)
    assert allowed is True, "чужий IP покараний за сусіда"


async def test_fallback_is_per_bucket():
    broken = _BrokenRedis()
    for _ in range(6):
        await rl.check_rate_limit(broken, "auth_verify", "1.2.3.4", 5)

    allowed, _, _ = await rl.check_rate_limit(broken, "admin_login", "1.2.3.4", 5)
    assert allowed is True, "бакети не ізольовані"


async def test_all_critical_buckets_are_registered():
    """
    Список критичних бакетів має покривати реальні auth-ендпоінти.
    Якщо ендпоінт перейменують — тест нагадає оновити CRITICAL_BUCKETS.
    """
    for bucket in ("auth_challenge", "auth_verify", "admin_login",
                   "federation_handshake"):
        assert bucket in rl.CRITICAL_BUCKETS


async def test_window_rollover_clears_counts():
    """Лічильник не росте вічно — вікно скидається щохвилини."""
    limiter = rl._LocalFallbackLimiter()
    limiter.hit("auth_verify", "1.2.3.4", 5)
    limiter._window -= 1  # імітуємо перехід у нову хвилину
    allowed, count = limiter.hit("auth_verify", "1.2.3.4", 5)
    assert (allowed, count) == (True, 1)
    assert len(limiter._counts) == 1, "старі вікна не прибираються"


async def test_healthy_redis_path_unaffected(redis):
    """Зі здоровим Redis поведінка не змінилась."""
    limit = 3
    results = [
        (await rl.check_rate_limit(redis, "auth_verify", "9.9.9.9", limit))[0]
        for _ in range(limit + 2)
    ]
    assert results[:limit] == [True] * limit
    assert results[limit:] == [False] * 2
    # локальний резерв не задіювався
    assert not rl._local_fallback._counts


async def test_backup_restore_is_critical():
    """
    Публічний restore віддає зашифрований seed за username. Fail-open
    при падінні Redis = безлімітне викачування блобів під offline-перебір
    PIN'а. Тест гарантує, що бакет лишається критичним.
    """
    assert "backup_restore" in rl.CRITICAL_BUCKETS
