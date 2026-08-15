"""
Morok Relay — main FastAPI application.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .api import account, admin, auth, backup, burner, dms, federation, groups, inbox, mail, messages, push, sealed, users
from .cleanup import cleanup_task_loop
from .config import get_settings
from .db import lifespan as db_lifespan
from .schemas import ErrorResponse, HealthResponse

logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Combined lifespan: bring up DB+Redis (via db_lifespan), then start
    the background cleanup task. Cancel it on shutdown.
    """
    async with db_lifespan(app):
        cleanup_task = asyncio.create_task(cleanup_task_loop())
        logger.info("Background cleanup task started")
        try:
            yield
        finally:
            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass
            logger.info("Background cleanup task stopped")


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


# ============================================================================
# CORS — allow the Capacitor mobile app (Android+iOS) to call the API.
# ============================================================================
#
# The web client lives on the SAME origin as the relay (https://relay1.morok.app
# serves both the API and /web/), so for browser users CORS is irrelevant —
# same-origin requests aren't subject to it. The mobile app, however, runs
# inside a WebView whose origin is one of these constants depending on
# platform and Capacitor version:
#
#   Android default:           http://localhost  (Capacitor's local HTTP server)
#   iOS default:               capacitor://localhost
#   Older Capacitor / config:  https://localhost
#
# We allow all three. We do NOT allow_credentials — auth is via the
# Authorization header (Bearer token), not cookies, so credential-less
# CORS is sufficient and avoids the "no wildcard with credentials" footgun.
#
# We don't allow arbitrary origins ("*") because that would let any random
# webpage's JavaScript hit our API from a logged-in user's browser. The
# narrow allow-list below restricts to our own mobile builds.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "https://localhost",
        "capacitor://localhost",
        "http://tauri.localhost",
        "https://tauri.localhost",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Server"] = "morok-relay"
    return response


# Шляхи, де сегмент URL сам є обліковим даним. Логувати їх повністю =
# роздати секрети всім, хто має доступ до журналів, бекапів чи збору логів.
#
# K7: burner-токен (багаторазовий, TTL до 30 днів) стоїть у шляху й не
# має жодної авторизації — токен САМ є доступом. Той, хто прочитає лог,
# може писати від імені будь-якого анонімного відправника. Те саме менш
# гостро стосується поштових аліасів (розкриває, які адреси в кого є).
#
# Маскуємо ЗА РЕГУЛЯРКАМИ, а не за списком точних шляхів: новий маршрут із
# токеном у path автоматично підпаде під шаблон, не чекаючи, поки хтось
# згадає оновити middleware.
_SENSITIVE_PATH_PATTERNS = [
    # /api/v1/burner/{token}, /public/{token}, /public/{token}/send
    (re.compile(r"(/api/v1/burner)(/public)?/[^/]+(/send)?$"),
     lambda m: f"{m.group(1)}{m.group(2) or ''}/***{m.group(3) or ''}"),
    # /api/v1/mail/aliases/{alias}[/label|/pause|/resume], /resolve/{alias}
    (re.compile(r"(/api/v1/mail/(?:aliases|resolve))/[^/]+(/\w+)?$"),
     lambda m: f"{m.group(1)}/***{m.group(2) or ''}"),
    # /api/v1/groups/by-slug/{slug}
    (re.compile(r"(/api/v1/groups/by-slug)/[^/]+$"),
     lambda m: f"{m.group(1)}/***"),
]


def _sanitize_path(path: str) -> str:
    for pattern, repl in _SENSITIVE_PATH_PATTERNS:
        new = pattern.sub(repl, path)
        if new != path:
            return new
    return path


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.monotonic()
    response = await call_next(request)
    elapsed_ms = (time.monotonic() - start) * 1000
    logger.info(
        "%s %s -> %d (%.1fms)",
        request.method,
        _sanitize_path(request.url.path),
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
    # _sanitize_path обов'язково і ТУТ (аудит зовн. №2): звичайний
    # request-логер маскує capability-токени в URL, а цей шлях — ні.
    # Достатньо було unhandled exception на burner-маршруті — і
    # довгоживучий токен (сам по собі credential) падав у журнал.
    logger.exception(
        "Unhandled exception on %s %s",
        request.method, _sanitize_path(request.url.path),
    )
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
app.include_router(account.router, prefix="/api/v1")
app.include_router(messages.router, prefix="/api/v1/messages")
app.include_router(groups.router, prefix="/api/v1/groups")
app.include_router(dms.router, prefix="/api/v1/dms")
app.include_router(burner.router, prefix="/api/v1/burner")
app.include_router(mail.router, prefix="/api/v1/mail")
app.include_router(federation.router, prefix="/api/v1/federation")
app.include_router(backup.router, prefix="/api/v1/backup")
app.include_router(admin.router, prefix="/api/v1/admin")
app.include_router(push.router, prefix="/api/v1/push")
app.include_router(sealed.router, prefix="/api/v1")

# WebSocket
app.include_router(inbox.router, prefix="/ws/v1")
