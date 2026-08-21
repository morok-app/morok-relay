"""
Sealed sender InboxToken registration — атомарний check-then-evict-
then-insert (жорсткий свіжий прохід — той самий клас race, знайдений
тим самим заходом у burner_tokens/invite_tokens/push subscriptions).

Наслідок тут м'якший за push quota: eviction, не hard rejection —
наступний register сам довів би кількість до норми. pg_advisory_
xact_lock прибирає навіть це тимчасове перевищення, тим самим
перевіреним підходом.

ПРО МЕЖІ CONCURRENCY-ТЕСТУ ТУТ (див. детальне пояснення в
test_push_quota_atomic.py): справжній asyncio.Barrier прямо перед
критичною секцією, захищеною advisory lock, зависає на фікс-версії —
lock фізично не пускає N транзакцій туди одночасно. Тому тут — той
самий м'який sleep-based підхід: тест підтверджує, що фікс не ламає
звичайну поведінку під конкурентним навантаженням, без deadlock.
"""
from __future__ import annotations

import asyncio

import pytest

pytestmark = pytest.mark.asyncio

OWNER = "aa" * 32


async def test_register_new_hash_succeeds(db):
    from morok_relay.api.sealed import InboxTokenRegisterRequest, register_inbox_token
    from morok_relay.sessions import Session

    session = Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)
    result = await register_inbox_token(
        InboxTokenRegisterRequest(token_hash="aa" * 32), session, db,
    )
    assert result == {"registered": True, "rotated": False}


async def test_reregister_same_hash_is_noop(db):
    from morok_relay.api.sealed import InboxTokenRegisterRequest, register_inbox_token
    from morok_relay.sessions import Session

    session = Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)
    h = "bb" * 32
    await register_inbox_token(InboxTokenRegisterRequest(token_hash=h), session, db)
    result = await register_inbox_token(
        InboxTokenRegisterRequest(token_hash=h), session, db,
    )
    assert result == {"registered": True, "rotated": False}


async def test_eviction_beyond_cap(db):
    """Понад MAX_TOKENS_PER_PUBKEY — найстаріші витісняються, кількість
    рядків не перевищує стелю."""
    from sqlalchemy import func, select

    from morok_relay.api.sealed import (
        MAX_TOKENS_PER_PUBKEY,
        InboxTokenRegisterRequest,
        register_inbox_token,
    )
    from morok_relay.models import InboxToken
    from morok_relay.sessions import Session

    session = Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)
    for i in range(MAX_TOKENS_PER_PUBKEY + 5):
        await register_inbox_token(
            InboxTokenRegisterRequest(token_hash=f"{i:064x}"), session, db,
        )

    count = (await db.execute(
        select(func.count()).select_from(InboxToken)
        .where(InboxToken.pubkey == bytes.fromhex(OWNER))
    )).scalar_one()
    assert count <= MAX_TOKENS_PER_PUBKEY


async def test_concurrent_register_same_hash_stays_idempotent(
    pg_sessionmaker, monkeypatch,
):
    """
    ГОЛОВНИЙ ТЕСТ — і не той сценарій, який я тестував першою спробою
    (різні хеші перевіряють лише "не падає"). Реальний ризик гонки тут
    — НЕ перевищення ліміту (eviction самокоригується при наступному
    register), а ІДЕМПОТЕНТНІСТЬ: якщо два пристрої (чи один клієнт із
    retry при мережевій нестабільності) одночасно реєструють ТОЙ САМИЙ
    token_hash, обидва можуть прочитати "хеша ще немає" (застарілий
    стан ДО insert одне одного) і обидва спробувати INSERT — другий
    впаде з IntegrityError (UniqueConstraint) замість очікуваного
    тихого no-op (registered=True, rotated=False). advisory lock
    серіалізує так, що друга спроба бачить УЖЕ вставлений хеш і
    коректно no-op'ить, а не падає.
    """
    import morok_relay.api.sealed as sealed_mod
    from morok_relay import db as db_module
    from morok_relay.api.sealed import InboxTokenRegisterRequest
    from morok_relay.sessions import Session

    monkeypatch.setattr(db_module, "_session_factory", pg_sessionmaker)

    session = Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)
    n = 5
    same_hash = "cc" * 32
    real_fetch = sealed_mod._fetch_inbox_tokens_for_pubkey

    async def delayed_fetch(db_, pk):
        await asyncio.sleep(0.05)
        return await real_fetch(db_, pk)

    sealed_mod._fetch_inbox_tokens_for_pubkey = delayed_fetch

    async def try_register() -> bool:
        async with pg_sessionmaker() as own_db:
            try:
                await sealed_mod.register_inbox_token(
                    InboxTokenRegisterRequest(token_hash=same_hash),
                    session, own_db,
                )
                await own_db.commit()
                return True
            except Exception:
                await own_db.rollback()
                return False

    try:
        results = await asyncio.gather(*[try_register() for _ in range(n)])
    finally:
        sealed_mod._fetch_inbox_tokens_for_pubkey = real_fetch

    assert all(results), \
        "конкурентна реєстрація ТОГО САМОГО хеша не мала падати нікому"

    from sqlalchemy import select

    from morok_relay.models import InboxToken
    async with pg_sessionmaker() as check_db:
        rows = (await check_db.execute(
            select(InboxToken)
            .where(InboxToken.pubkey == bytes.fromhex(OWNER))
            .where(InboxToken.token_hash == same_hash)
        )).scalars().all()
    assert len(rows) == 1, \
        f"той самий хеш вставлено {len(rows)} разів замість рівно 1"
