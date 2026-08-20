"""
Burner tokens: атомарний ліміт активних токенів (жорсткий свіжий
прохід — burner_tokens.py взагалі не мав власного тестового файлу
раніше).

Знахідка: count_active_tokens() (читання) і create_token() (запис)
були окремими операціями — той самий клас check-then-insert race, що
вже закривали для inbox depth, group capacity, DMS quota. Складніше
за звичайний EVAL-guard: наявна логіка ТЕЖ чистила stale-членів SET
перед підрахунком, тому Lua-скрипт мусить робити те саме атомарно, а
не просто SCARD (інакше — false positives для власників із
протухлими, ще не вичищеними токенами).
"""
from __future__ import annotations

import asyncio

import pytest

from morok_relay import burner_tokens as bt

pytestmark = pytest.mark.asyncio

OWNER = "aa" * 32


# ── звичайний шлях ────────────────────────────────────────────────────────
async def test_create_token_succeeds_under_limit(redis):
    info = await bt.create_token(redis, OWNER)
    assert info is not None
    assert info["owner_pubkey_hex"] == OWNER


async def test_create_token_returns_none_at_limit(redis):
    for _ in range(bt.MAX_ACTIVE_TOKENS_PER_OWNER):
        info = await bt.create_token(redis, OWNER)
        assert info is not None
    over_limit = await bt.create_token(redis, OWNER)
    assert over_limit is None


async def test_revoke_frees_a_slot(redis):
    infos = [await bt.create_token(redis, OWNER)
             for _ in range(bt.MAX_ACTIVE_TOKENS_PER_OWNER)]
    assert await bt.create_token(redis, OWNER) is None

    await bt.revoke_token(redis, OWNER, infos[0]["token"])
    freed = await bt.create_token(redis, OWNER)
    assert freed is not None


# ── stale cleanup всередині атомарного кроку ─────────────────────────────
async def test_expired_token_in_set_does_not_block_new_creation(redis):
    """
    ГОЛОВНИЙ ТЕСТ на другу половину знахідки. Owner-SET містить
    MAX_ACTIVE_TOKENS_PER_OWNER "токенів", але їхні Redis-ключі вже
    протухли (TTL вичерпано) — стале member лишилось у SET, поки ніхто
    не читав list_tokens_for_owner. Атомарний Lua має ЦЕ побачити й
    вичистити, а НЕ відмовити через застарілий підрахунок.
    """
    owner_key = bt._owner_key(OWNER)
    for i in range(bt.MAX_ACTIVE_TOKENS_PER_OWNER):
        fake_token = f"stale-token-{i}"
        await redis.sadd(owner_key, fake_token)
        # НЕ створюємо відповідний token_key — імітує вже протухлий ключ.

    # Наївний SCARD дав би MAX_ACTIVE_TOKENS_PER_OWNER і відмовив би.
    result = await bt.create_token(redis, OWNER)
    assert result is not None, \
        "відмова через застарілі (протухлі) записи в owner-SET"

    # Stale-члени мали бути вичищені як побічний ефект.
    remaining_stale = await redis.sismember(owner_key, "stale-token-0")
    assert not remaining_stale


async def test_mixed_alive_and_stale_counts_only_alive(redis):
    """Частина токенів справді жива, частина — застарілі сліди в SET.
    Ліміт рахується лише за живими."""
    owner_key = bt._owner_key(OWNER)
    half = bt.MAX_ACTIVE_TOKENS_PER_OWNER // 2

    for _i in range(half):
        await bt.create_token(redis, OWNER)  # реально живі

    for i in range(half):
        await redis.sadd(owner_key, f"phantom-{i}")  # застарілі сліди

    # half живих + half фантомних = MAX; але фантомні мають бути
    # проігноровані/вичищені, тож місце під ЖИВІ токени лишається.
    result = await bt.create_token(redis, OWNER)
    assert result is not None


# ── справжня паралельна гонка ─────────────────────────────────────────────
async def test_concurrent_create_never_exceeds_limit(redis):
    """
    ГОЛОВНИЙ ТЕСТ атомарності. Ліміт майже вичерпаний (MAX-1 токенів),
    десять паралельних create_token на останнє вільне місце — атомарно
    має пройти рівно один. Redis EVAL сам по собі однопотоковий на
    сервері, тож на відміну від Postgres-тестів тут не потрібен
    asyncio.Barrier — паралельні EVAL-виклики природно серіалізуються
    самим Redis.
    """
    for _ in range(bt.MAX_ACTIVE_TOKENS_PER_OWNER - 1):
        await bt.create_token(redis, OWNER)

    results = await asyncio.gather(
        *[bt.create_token(redis, OWNER) for _ in range(10)]
    )
    succeeded = [r for r in results if r is not None]
    assert len(succeeded) == 1, \
        f"прийнято {len(succeeded)} нових токенів замість рівно 1"

    active = await bt.count_active_tokens(redis, OWNER)
    assert active == bt.MAX_ACTIVE_TOKENS_PER_OWNER


# ── наскрізно через API-ендпоінт ──────────────────────────────────────────
async def test_endpoint_returns_409_at_limit(redis):
    from fastapi import HTTPException

    from morok_relay.api.burner import create_burner_token
    from morok_relay.schemas import BurnerCreate
    from morok_relay.sessions import Session

    session = Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)
    for _ in range(bt.MAX_ACTIVE_TOKENS_PER_OWNER):
        await create_burner_token(BurnerCreate(), session, redis)

    with pytest.raises(HTTPException) as e:
        await create_burner_token(BurnerCreate(), session, redis)
    assert e.value.status_code == 409
    assert "too_many_active_burner_links" in e.value.detail
