"""
Спільні фікстури тестів.

Вимоги середовища (CI ставить у workflow, локально — руками):
  * Redis на localhost:6399 (або MOROK_TEST_REDIS_URL)
  * PostgreSQL з БД morok_test / роль morok_test:test superuser
    (або MOROK_TEST_DB_DSN)

Кожен тест отримує ЧИСТИЙ стан: Redis — flushdb окремої логічної БД,
Postgres — drop_all/create_all на初 кожної сесії + TRUNCATE між тестами.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# ── env ДО імпорту config: Settings кешується через lru_cache ──────────
TEST_REDIS_URL = os.environ.get("MOROK_TEST_REDIS_URL", "redis://localhost:6399/0")
TEST_DB_DSN = os.environ.get(
    "MOROK_TEST_DB_DSN",
    "postgresql+asyncpg://morok_test:test@localhost:5432/morok_test",
)
os.environ.setdefault("MOROK_REDIS_URL", TEST_REDIS_URL)
os.environ.setdefault("MOROK_DB_DSN", TEST_DB_DSN)
# Валідна Ed25519-пара потрібна dms_reaper'у (детермінована, тестова).
os.environ.setdefault(
    "MOROK_RELAY_PRIVKEY_HEX",
    "1f" * 32,
)
os.environ.setdefault(
    "MOROK_RELAY_PUBKEY_HEX",
    "2e" * 32,
)
os.environ.setdefault("MOROK_MAIL_OUT_TOKEN", "test-worker-token")
os.environ.setdefault("MOROK_IS_PRODUCTION", "false")

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402


def pytest_collection_modifyitems(items):
    """Один event loop на всю сесію: session-scoped async-фікстури
    (pg_engine) мають жити на тому ж лупі, що й тести."""
    for item in items:
        if item.get_closest_marker("asyncio") is not None:
            item.add_marker(pytest.mark.asyncio(loop_scope="session"))

import redis.asyncio as redis_async  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import morok_relay.mail_models  # noqa: E402,F401  — реєструє таблиці в Base
from morok_relay.config import get_settings  # noqa: E402
from morok_relay.models import Base  # noqa: E402

get_settings.cache_clear()


# ── Redis ────────────────────────────────────────────────────────────────
@pytest_asyncio.fixture
async def redis():
    """Чистий Redis на тест. Логічна БД 12 — тільки тестова."""
    url = TEST_REDIS_URL.rsplit("/", 1)[0] + "/12"
    r = redis_async.from_url(url, max_connections=250)
    await r.flushdb()
    yield r
    await r.flushdb()
    await r.aclose()


# ── Postgres ─────────────────────────────────────────────────────────────
@pytest_asyncio.fixture(scope="session")
async def pg_engine():
    engine = create_async_engine(TEST_DB_DSN, pool_size=10, max_overflow=10)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def pg_sessionmaker(pg_engine):
    """Фабрика сесій + TRUNCATE всіх таблиць після тесту."""
    factory = async_sessionmaker(pg_engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    from sqlalchemy import text
    async with pg_engine.begin() as conn:
        tables = ", ".join(t.name for t in Base.metadata.sorted_tables)
        await conn.execute(text(f"TRUNCATE {tables} CASCADE"))


@pytest_asyncio.fixture
async def db(pg_sessionmaker):
    async with pg_sessionmaker() as session:
        yield session


# ── дрібні хелпери ───────────────────────────────────────────────────────
@pytest.fixture
def fake_session():
    """CurrentSession-сумісний об'єкт для прямого виклику route-функцій."""
    from morok_relay.sessions import Session

    def _make(pubkey_hex: str) -> Session:
        return Session(token="t" * 64, pubkey_hex=pubkey_hex, expires_at=2**31)

    return _make
