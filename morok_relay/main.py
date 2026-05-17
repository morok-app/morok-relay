"""
Morok Relay — main FastAPI application.
"""
from __future__ import annotations

import logging
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from . import __version__
from .api import auth, dms, federation, groups, inbox, messages, users
from .config import get_settings
from .db import lifespan
from .schemas import ErrorResponse, HealthResponse

logger = logging.getLogger(__name__)

settings = get_settings()

app = FastAPI(
    title="Morok Relay",
    description=(
        "Federated relay server for the Morok messenger. "
        "Stores nothing in plaintext, ever."
    ),
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    openapi_url="/openapi.json" if not settings.is_production else None,
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Server"] = "morok-relay"
    return response


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.monotonic()
    response = await call_next(request)
    elapsed_ms = (time.monotonic() - start) * 1000
    logger.info(
        "%s %s -> %d (%.1fms)",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error=exc.detail).model_dump(exclude_none=True),
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    if settings.debug:
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="internal_server_error",
                detail=f"{type(exc).__name__}: {exc}",
            ).model_dump(exclude_none=True),
        )
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(error="internal_server_error").model_dump(exclude_none=True),
    )


@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    onion = settings.tor_onion_address or None
    return HealthResponse(
        status="ok",
        relay_name=settings.relay_name,
        version=__version__,
        onion=onion,
        onion_supported=bool(onion),
    )


@app.get("/", tags=["meta"])
async def root():
    return {"name": "morok-relay", "version": __version__}


# ============================================================================
# API ROUTERS
# ============================================================================

app.include_router(auth.router, prefix="/api/v1/auth")
app.include_router(users.router, prefix="/api/v1/users")
app.include_router(messages.router, prefix="/api/v1/messages")
app.include_router(groups.router, prefix="/api/v1/groups")
app.include_router(dms.router, prefix="/api/v1/dms")
app.include_router(federation.router, prefix="/api/v1/federation")

# WebSocket
app.include_router(inbox.router, prefix="/ws/v1")
