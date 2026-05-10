"""
Morok Relay — main FastAPI application.

This is the entry point. Run with:
    uvicorn morok_relay.main:app --reload

In production, use the included gunicorn config (deploy/gunicorn.conf.py).
"""
from __future__ import annotations

import logging
import time

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from . import __version__
from .config import get_settings
from .db import lifespan
from .schemas import ErrorResponse, HealthResponse

logger = logging.getLogger(__name__)


# ============================================================================
# APP
# ============================================================================

settings = get_settings()

app = FastAPI(
    title="Morok Relay",
    description=(
        "Federated relay server for the Morok messenger. "
        "Stores nothing in plaintext, ever."
    ),
    version=__version__,
    lifespan=lifespan,
    # Disable docs in production — they leak the API surface
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    openapi_url="/openapi.json" if not settings.is_production else None,
)


# ============================================================================
# MIDDLEWARE — request logging, headers
# ============================================================================

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Add basic security headers. nginx will add more in production
    (HSTS, CSP, etc), but these are defaults that always apply.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Server"] = "morok-relay"  # don't reveal uvicorn version
    return response


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log requests minimally. Never log bodies or headers."""
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


# ============================================================================
# EXCEPTION HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Standardize error responses."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error=exc.detail).model_dump(exclude_none=True),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    Catch-all for unexpected errors.

    In production we never leak exception details to clients — log internally,
    return generic message externally.
    """
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


# ============================================================================
# ROUTES — minimal startup set
# ============================================================================

@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    """Liveness probe. Used by load balancer / orchestrator."""
    return HealthResponse(
        status="ok",
        relay_name=settings.relay_name,
        version=__version__,
    )


@app.get("/", tags=["meta"])
async def root():
    """Root endpoint. Intentionally minimal — no fingerprinting surface."""
    return {"name": "morok-relay", "version": __version__}


# ============================================================================
# ROUTERS — added incrementally as we build
# ============================================================================
# When ready, register routers here:
#   from .api import auth, users, messages, federation
#   app.include_router(auth.router,       prefix="/api/v1/auth")
#   app.include_router(users.router,      prefix="/api/v1/users")
#   app.include_router(messages.router,   prefix="/api/v1/messages")
#   app.include_router(federation.router, prefix="/api/v1/federation")
