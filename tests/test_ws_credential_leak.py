"""
Аудит зовн. №5, CRITICAL/P1 — WebSocket session bearer у journald +
WS переживає природну смерть сесії.

ЗЛОВЛЕНО ЖИВИМ ДОКАЗОМ: продакшн journald на relay1 реально містив
"WebSocket /ws/v1/inbox?token=<64-символьний bearer>" повним текстом —
uvicorn логує WS accept/reject через logger "uvicorn.error" (не
"uvicorn.access"), тож --no-access-log і nginx access_log off цього
не ловлять.

Другий незалежний баг: verify_session_token() викликається лише раз
при WS handshake; природне закінчення сесії (sliding TTL, 30-денна
стеля) ніколи не публікує подію — на відміну від explicit revoke — і
вже відкритий сокет жив би необмежено довго.
"""
from __future__ import annotations

import io
import logging
import time

import pytest

pytestmark = pytest.mark.asyncio


# ── uvicorn redaction filter ─────────────────────────────────────────────
def test_ws_token_redacted_in_uvicorn_error_log():
    """
    ГОЛОВНИЙ ТЕСТ. Відтворює ТОЧНИЙ живий запис, зловлений у
    продакшн journald на relay1 — перевіряє, що повний токен більше
    не проходить у форматований вивід.
    """

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    uv_logger = logging.getLogger("uvicorn.error")
    uv_logger.addHandler(handler)
    uv_logger.setLevel(logging.INFO)
    try:
        uv_logger.info(
            '%s - "%s" %s',
            "('194.242.100.78', 0)",
            "WebSocket /ws/v1/inbox?"
            "token=0782d856e6bcc6cd479401a65ef20538271eac0fa14f0b78da8cd658a0fbb5c4",
            "[accepted]",
        )
        output = stream.getvalue()
    finally:
        uv_logger.removeHandler(handler)

    assert "0782d856" not in output, "повний session bearer потрапив у лог"
    assert "[redacted]" in output
    assert "WebSocket /ws/v1/inbox" in output, \
        "фільтр надто агресивний — знищив diagnostic-цінність запису"


def test_uvicorn_access_log_also_redacted():
    """Той самий захист і на uvicorn.access — про всяк випадок, якщо
    хтось увімкне access-log попри дефолтне вимкнення в install.sh."""
    import morok_relay.main  # noqa

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    uv_logger = logging.getLogger("uvicorn.access")
    uv_logger.addHandler(handler)
    uv_logger.setLevel(logging.INFO)
    try:
        uv_logger.info(
            'GET /ws/v1/inbox?token=%s HTTP/1.1',
            "aa" * 32,
        )
        output = stream.getvalue()
    finally:
        uv_logger.removeHandler(handler)
    assert "aa" * 32 not in output


def test_redaction_does_not_touch_unrelated_logs():
    """Фільтр не має чіпати звичайні записи без token=/ticket=."""
    import morok_relay.main  # noqa

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    uv_logger = logging.getLogger("uvicorn.error")
    uv_logger.addHandler(handler)
    uv_logger.setLevel(logging.INFO)
    try:
        uv_logger.info("Application startup complete")
        output = stream.getvalue()
    finally:
        uv_logger.removeHandler(handler)
    assert "Application startup complete" in output


def test_redaction_handles_ticket_param_too():
    """Майбутній ticket-based шлях (?ticket=) теж підпадає під захист —
    заздалегідь, до того як сам ticket-механізм з'явиться."""
    import morok_relay.main  # noqa

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    uv_logger = logging.getLogger("uvicorn.error")
    uv_logger.addHandler(handler)
    uv_logger.setLevel(logging.INFO)
    try:
        uv_logger.info(
            'WebSocket /ws/v1/inbox?ticket=%s [accepted]', "bb" * 20,
        )
        output = stream.getvalue()
    finally:
        uv_logger.removeHandler(handler)
    assert "bb" * 20 not in output


# ── is_session_alive: non-refreshing check ───────────────────────────────
async def test_is_session_alive_true_for_fresh_session(redis):
    from morok_relay.sessions import create_session, is_session_alive
    s = await create_session(redis, "aa" * 32)
    assert await is_session_alive(redis, s.token) is True


async def test_is_session_alive_false_for_unknown_token(redis):
    from morok_relay.sessions import is_session_alive
    assert await is_session_alive(redis, "nonexistent" + "x" * 53) is False


async def test_is_session_alive_false_after_absolute_cap(redis):
    from morok_relay import sessions as ss
    s = await ss.create_session(redis, "bb" * 32)
    digest = ss._token_digest(s.token)
    key = ss._session_key(digest)
    old_created = int(time.time()) - ss.SESSION_ABSOLUTE_MAX_SECONDS - 100
    await redis.set(key, f"{'bb' * 32}|{old_created}".encode(), ex=3600)
    assert await ss.is_session_alive(redis, s.token) is False


async def test_is_session_alive_does_not_refresh_ttl(redis):
    """
    ГОЛОВНИЙ ТЕСТ семантики. is_session_alive() НЕ продовжує TTL — на
    відміну від verify_session_token(). Якби продовжував, pinger, що
    викликає його щоп'ятого пінгу, робив би сесію практично вічною для
    відкритого WS, зводячи нанівець сенс TTL.
    """
    from morok_relay import sessions as ss
    s = await ss.create_session(redis, "cc" * 32)
    digest = ss._token_digest(s.token)
    key = ss._session_key(digest)

    await redis.expire(key, 100)  # штучно стискаємо TTL
    ttl_before = await redis.ttl(key)

    assert await ss.is_session_alive(redis, s.token) is True

    ttl_after = await redis.ttl(key)
    assert ttl_after <= ttl_before, \
        "is_session_alive() продовжив TTL — сесія стане практично вічною"


async def test_verify_session_token_still_refreshes_ttl_for_contrast(redis):
    """Контроль: verify_session_token() (звичайний HTTP-шлях) і надалі
    коректно ковзає TTL — це не зламано новою функцією."""
    from morok_relay import sessions as ss
    s = await ss.create_session(redis, "dd" * 32)
    digest = ss._token_digest(s.token)
    key = ss._session_key(digest)

    await redis.expire(key, 100)
    assert await ss.verify_session_token(redis, s.token) is not None
    ttl_after = await redis.ttl(key)
    assert ttl_after > 100, "verify_session_token більше не ковзає TTL"


# ── pinger_task: закриває WS при природному протуханні ──────────────────
async def test_pinger_closes_socket_on_natural_expiry(redis, monkeypatch):
    """
    Наскрізна імітація сценарію з аудиту: токен украли → відкрили WS
    → токен природно протух (не explicit revoke) → pinger має
    ЗАКРИТИ сокет на наступному тику, а не тримати відкритим вічно.
    """
    from morok_relay import sessions as ss
    from morok_relay.api import inbox as inbox_mod

    s = await ss.create_session(redis, "ee" * 32)

    # Імітуємо природне протухання: видаляємо ключ сесії напряму
    # (те саме, що станеться, коли Redis сам зітре протухлий TTL-ключ).
    digest = ss._token_digest(s.token)
    await redis.delete(ss._session_key(digest))

    assert await ss.is_session_alive(redis, s.token) is False, \
        "тестова передумова: сесія має виглядати мертвою"

    # Перевіряємо саме той виклик, який pinger_task робить на кожному
    # тику — без піднімання повного WS з'єднання (це вже юніт-рівень
    # для самої умови закриття, наскрізний WS-тест — окремий рівень
    # інтеграції, тут важливо, що умова спрацьовує коректно).
    alive = await inbox_mod.is_session_alive(redis, s.token)
    assert alive is False
