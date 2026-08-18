"""
Database and Redis connection management.

Uses async SQLAlchemy 2.0 + asyncpg for Postgres, redis-py async for Redis.
Both are managed as application-lifetime resources via FastAPI's lifespan.
"""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import redis.asyncio as redis_async
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from .config import get_settings

logger = logging.getLogger(__name__)


# ============================================================================
# SQLAlchemy Base
# ============================================================================

class Base(DeclarativeBase):
    """Base class for all ORM models. SQLAlchemy 2.0 typed style."""
    pass


# ============================================================================
# Engine & session factory (singletons, set up at startup)
# ============================================================================

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None
_redis: redis_async.Redis | None = None


async def init_db() -> None:
    """Initialize database engine and session factory. Idempotent."""
    global _engine, _session_factory

    if _engine is not None:
        return

    settings = get_settings()

    _engine = create_async_engine(
        settings.db_dsn,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_pre_ping=True,           # check connection before use
        echo=settings.debug,           # log SQL in dev
    )

    _session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    logger.info("Database engine initialized: %s", _redact_dsn(settings.db_dsn))


async def init_redis() -> None:
    """Initialize Redis connection pool. Idempotent."""
    global _redis

    if _redis is not None:
        return

    settings = get_settings()

    _redis = redis_async.from_url(
        settings.redis_url,
        max_connections=settings.redis_pool_size,
        decode_responses=False,    # we deal in bytes for crypto
    )

    # Validate connection now, not at first use
    await _redis.ping()
    # Аудит зовн. №3, MEDIUM: DSN Postgres тут редагувався, Redis URL —
    # ні. redis://user:пароль@host потрапляв у journald повністю.
    logger.info("Redis connected: %s", _redact_dsn(settings.redis_url))


async def close_db() -> None:
    """Close database engine. Called at shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("Database engine closed")


async def close_redis() -> None:
    """Close Redis connection pool. Called at shutdown."""
    global _redis
    if _redis is not None:
        await _redis.aclose()
        _redis = None
        logger.info("Redis connection closed")


# ============================================================================
# Dependency injection helpers (used by FastAPI endpoints)
# ============================================================================

async def get_session() -> AsyncIterator[AsyncSession]:
    """
    Yield a database session. Use as a FastAPI dependency:

        @app.get("/foo")
        async def foo(session: AsyncSession = Depends(get_session)):
            ...

    Session is rolled back on unhandled exception, otherwise committed.
    """
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def get_redis() -> redis_async.Redis:
    """Get the Redis client. Use as a FastAPI dependency."""
    if _redis is None:
        raise RuntimeError("Redis not initialized. Call init_redis() first.")
    return _redis


# ============================================================================
# Lifespan context manager (used by FastAPI app)
# ============================================================================

@asynccontextmanager
async def lifespan(app):
    """
    FastAPI lifespan handler. Sets up DB/Redis at startup,
    tears down at shutdown.
    """
    await init_db()
    await init_redis()
    try:
        yield
    finally:
        await close_redis()
        await close_db()


# ============================================================================
# Helpers
# ============================================================================

def _redact_dsn(dsn: str) -> str:
    """Hide password in DSN for logging."""
    if "@" not in dsn or "://" not in dsn:
        return dsn
    proto, rest = dsn.split("://", 1)
    if "@" in rest:
        creds, host = rest.rsplit("@", 1)
        if ":" in creds:
            user, _ = creds.split(":", 1)
            return f"{proto}://{user}:***@{host}"
    return dsn
