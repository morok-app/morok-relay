"""
Username churn / namespace squatting (аудит зовн. №3, HIGH).

Знахідка: POST /me/username не мав ЖОДНОГО rate-limit dependency і,
головне, жодного обмеження на ЧАСТОТУ ВЛАСНИХ змін. username_cooldown_
days захищає ІНШИХ (звільнене ім'я недоступне їм якийсь час), але не
обмежує САМ акаунт: бот міг пройти словник хороших username'ів за
секунди — claim "alice1" → одразу claim "bravo1" → claim "charlie" → ...,
блокуючи кожне на 30 днів для решти світу.

Фікс — два шари: rate-limit dependency (частота HTTP-запитів) + сервер-
на мінімальна відстань між ФАКТИЧНИМИ змінами (реальна стеля проти
проходу по словнику, не обходиться навіть повільним ботом).
"""
from __future__ import annotations

import time

import pytest
from fastapi import HTTPException

from morok_relay.api.users import claim_username
from morok_relay.models import User, UserTier
from morok_relay.schemas import UsernameClaim
from morok_relay.sessions import Session

pytestmark = pytest.mark.asyncio

OWNER = "aa" * 32


def _session() -> Session:
    return Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)


async def _ensure_user(db, username: str | None = None) -> User:
    from sqlalchemy import select

    from morok_relay.config import get_settings
    pk = bytes.fromhex(OWNER)
    existing = (await db.execute(
        select(User).where(User.pubkey == pk)
    )).scalar_one_or_none()
    if existing is None:
        user = User(pubkey=pk, tier=UserTier.FREE, username=username,
                    home_relay=get_settings().relay_name,
                    created_at=int(time.time()),
                    last_seen_at=int(time.time()))
        db.add(user)
        await db.commit()
        return user
    return existing


# ── перший claim без обмежень ────────────────────────────────────────────
async def test_first_claim_has_no_interval_restriction(db):
    """Свіжий акаунт (username IS NULL) — перша реєстрація завжди проходить."""
    await _ensure_user(db, username=None)
    result = await claim_username(
        UsernameClaim(username="freshstart"), _session(), db,
    )
    assert result.username == "freshstart"


# ── ГОЛОВНЕ: другу зміну зразу після першої блокує ───────────────────────
async def test_rapid_second_change_blocked(db):
    """
    Саме сценарій з аудиту: claim "alice1" → одразу claim "bravo1" — друга
    зміна має впертись у мінімальний інтервал.
    """
    await _ensure_user(db, username=None)
    await claim_username(UsernameClaim(username="alice1"), _session(), db)

    with pytest.raises(HTTPException) as e:
        await claim_username(UsernameClaim(username="bravo1"), _session(), db)
    assert e.value.status_code == 429
    assert e.value.detail == "username_changed_too_recently"
    assert "Retry-After" in e.value.headers


async def test_change_allowed_after_interval_elapses(db, monkeypatch):
    """Через належний час — зміна знову дозволена."""
    import morok_relay.api.users as users_mod
    monkeypatch.setattr(
        users_mod.get_settings(), "username_change_min_interval_seconds", 5,
    )

    await _ensure_user(db, username=None)
    await claim_username(UsernameClaim(username="patient"), _session(), db)

    # штучно відсуваємо username_changed_at у минуле — за межу інтервалу
    from sqlalchemy import update
    await db.execute(
        update(User)
        .where(User.pubkey == bytes.fromhex(OWNER))
        .values(username_changed_at=int(time.time()) - 10)
    )
    await db.commit()

    result = await claim_username(UsernameClaim(username="patient2"), _session(), db)
    assert result.username == "patient2"


async def test_same_username_reclaim_is_noop_not_blocked(db):
    """
    Заявити ТЕ САМЕ ім'я, яке вже маєш — рання гілка "no-op", не
    зачіпає інтервал взагалі (це не churn).
    """
    await _ensure_user(db, username=None)
    await claim_username(UsernameClaim(username="stable"), _session(), db)
    result = await claim_username(UsernameClaim(username="stable"), _session(), db)
    assert result.username == "stable"


async def test_bot_cannot_walk_dictionary_of_names(db):
    """
    Наскрізна імітація атаки з аудиту: спроба захопити 5 імен поспіль
    одним акаунтом — лише перше проходить, решта впираються в інтервал.
    """
    await _ensure_user(db, username=None)
    succeeded = 0
    for name in ("nameone", "nametwo", "namethree", "namefour", "namefive"):
        try:
            await claim_username(UsernameClaim(username=name), _session(), db)
            succeeded += 1
        except HTTPException as e:
            assert e.status_code == 429
    assert succeeded == 1, \
        f"бот захопив {succeeded} імен замість 1 — namespace squatting не закрито"


# ── rate-limit dependency присутній ──────────────────────────────────────
async def test_rate_limit_dependency_registered():
    """
    Перевіряємо, що депенденсі справді підключена до маршруту (а не
    просто існує функція десь у коді).
    """
    from morok_relay.api.users import router
    route = next(r for r in router.routes if r.path == "/me/username")
    dep_names = [
        getattr(d.call, "__qualname__", str(d.call))
        for d in route.dependant.dependencies
    ]
    assert any("rate_limit" in name for name in dep_names), \
        "claim_username без rate-limit dependency"
