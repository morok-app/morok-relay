"""
FastAPI dependency injection helpers.

These are used in route signatures via `Depends(...)` — see api/users.py
for examples.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_redis, get_session
from .sessions import Session, verify_session_token


async def get_current_session(
    redis: Annotated[Redis, Depends(get_redis)],
    authorization: Annotated[str | None, Header()] = None,
) -> Session:
    """
    Extract and verify a session token from the Authorization header.

    Expected format:  Authorization: Bearer <token_hex>

    Returns the Session (with .pubkey_hex) if valid; raises 401 otherwise.

    Used as `current: Session = Depends(get_current_session)` in endpoints.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing_authorization",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_authorization_scheme",
            headers={"WWW-Authenticate": "Bearer"},
        )

    session = await verify_session_token(redis, token.strip())
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_or_expired_token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return session


# Convenience type aliases — make endpoint signatures shorter
CurrentSession = Annotated[Session, Depends(get_current_session)]
DBSession = Annotated[AsyncSession, Depends(get_session)]
RedisClient = Annotated[Redis, Depends(get_redis)]
