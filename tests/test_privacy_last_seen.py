"""
Публічний lookup більше не видає last_seen_at (аудит зовн. №3, HIGH,
privacy).

Знахідка: /users/lookup/{username} без авторизації повертав точний
last_seen_at — regular polling перетворював релей на presence oracle
("коли ця людина востаннє була активна") для будь-кого, хто знає
@username. Колонка в БД лишається (потрібна для cleanup), прибрана
саме публічна видача.
"""
from __future__ import annotations

import time

import pytest

from morok_relay.models import User, UserTier
from morok_relay.schemas import UserInfo

pytestmark = pytest.mark.asyncio


# ── схема ────────────────────────────────────────────────────────────────
async def test_userinfo_schema_has_no_last_seen_field():
    """
    ГОЛОВНИЙ ТЕСТ. Поле прибране з самої схеми — якщо хтось коли-небудь
    спробує повернути last_seen_at через UserInfo, Pydantic мовчки
    проігнорує зайвий kwarg лише якщо це задокументована поведінка;
    перевіряємо явно, що поля немає в моделі.
    """
    assert "last_seen_at" not in UserInfo.model_fields


async def test_userinfo_construction_silently_drops_last_seen_at():
    """
    Pydantic v2 за замовчуванням ігнорує зайві kwargs (extra="ignore"),
    тому навіть якщо хтось випадково передасть last_seen_at, воно НЕ
    потрапить у серіалізовану відповідь — перевіряємо саме це, а не
    сам факт прийняття виклику.
    """
    info = UserInfo(
        pubkey_hex="aa" * 32, username="x",
        home_relay="relay1.morok.app", last_seen_at=123,  # type: ignore[call-arg]
    )
    assert "last_seen_at" not in info.model_dump()


# ── наскрізно: локальний lookup не витікає активність ────────────────────
async def test_local_lookup_does_not_leak_last_seen(db):
    """
    Користувач був активний хвилину тому — публічний lookup цього не
    показує, попри те, що last_seen_at у БД коректно оновлений.
    """
    from morok_relay.api.users import lookup_username
    from morok_relay.config import get_settings

    settings = get_settings()
    now = int(time.time())
    db.add(User(
        pubkey=b"\x99" * 32, username="privacyconscious",
        home_relay=settings.relay_name, tier=UserTier.FREE,
        created_at=now - 86400, last_seen_at=now - 60,  # активний хвилину тому
    ))
    await db.commit()

    result = await lookup_username("privacyconscious", db, redis=None)

    assert not hasattr(result, "last_seen_at") or result.last_seen_at is None
    dumped = result.model_dump()
    assert "last_seen_at" not in dumped, \
        "публічний lookup досі містить presence-мітку"


async def test_lookup_still_returns_useful_fields(db):
    """Фікс не повинен ламати сам lookup — pubkey/username/home_relay
    досі на місці."""
    from morok_relay.api.users import lookup_username
    from morok_relay.config import get_settings

    settings = get_settings()
    now = int(time.time())
    db.add(User(
        pubkey=b"\x88" * 32, username="stillfindable",
        home_relay=settings.relay_name, tier=UserTier.FREE,
        created_at=now, last_seen_at=now,
    ))
    await db.commit()

    result = await lookup_username("stillfindable", db, redis=None)
    assert result.username == "stillfindable"
    assert result.pubkey_hex == ("88" * 32)
    assert result.home_relay == settings.relay_name


# ── federation-хендлер (host-бік) уже був чистим — фіксуємо контракт ─────
async def test_federation_lookup_handler_never_included_last_seen(db):
    """
    Наш relay як HOST для чужого federation-запиту теж не мав /не має
    віддавати last_seen_at — цей тест лише закріплює вже правильну
    поведінку, щоб регресія (додавання поля назад) була помітна.
    """
    from morok_relay.api.federation import federation_lookup
    from morok_relay.config import get_settings

    settings = get_settings()
    now = int(time.time())
    db.add(User(
        pubkey=b"\x66" * 32, username="hostside",
        home_relay=settings.relay_name, tier=UserTier.FREE,
        created_at=now, last_seen_at=now,
    ))
    await db.commit()

    result = await federation_lookup("hostside", db)
    assert "last_seen_at" not in result
