"""
Сесії: хешовані токени в Redis (аудит 3, P2) + контракт revoke↔WS.

Перевіряємо:
  * у Redis лежить лише SHA-256, plaintext-токена немає ніде;
  * легасі-сесія (plaintext-ключ) мігрує на льоту при verify;
  * revoke_session / revoke_all_sessions працюють для ОБОХ поколінь;
  * revoke публікує session_revoked із правильним token_hash у канал,
    який слухають живі WebSocket'и (те, що закриває вкрадений сокет).
"""
from __future__ import annotations

import asyncio
import hashlib
import json

import pytest

from morok_relay import sessions as ss

pytestmark = pytest.mark.asyncio


async def _next_event(ch, timeout=3.0):
    """Дочекатись першого справжнього повідомлення в pubsub."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        msg = await ch.get_message(ignore_subscribe_messages=True, timeout=0.2)
        if msg is not None:
            return msg
    return None

PK = "cc" * 32


def _dg(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def test_create_stores_digest_only(redis):
    s = await ss.create_session(redis, PK)
    assert await redis.get(f"morok:session:{_dg(s.token)}") is not None
    assert await redis.get(f"morok:session:{s.token}") is None
    members = {m.decode() for m in await redis.smembers(f"morok:user_sessions:{PK}")}
    assert members == {_dg(s.token)}


async def test_verify_and_sliding_ttl(redis):
    s = await ss.create_session(redis, PK)
    v = await ss.verify_session_token(redis, s.token)
    assert v is not None and v.pubkey_hex == PK
    assert await ss.verify_session_token(redis, "0" * 64) is None


async def test_legacy_session_migrates_on_verify(redis):
    """Сесія старого формату проходить verify і переїжджає на digest."""
    legacy = ss.generate_token()
    await redis.set(f"morok:session:{legacy}", PK.encode(), ex=3600)
    await redis.sadd(f"morok:user_sessions:{PK}", legacy.encode())

    v = await ss.verify_session_token(redis, legacy)
    assert v is not None and v.pubkey_hex == PK

    # plaintext-ключа більше немає, digest існує, reverse-сет оновлено
    assert await redis.get(f"morok:session:{legacy}") is None
    assert await redis.get(f"morok:session:{_dg(legacy)}") is not None
    members = {m.decode() for m in await redis.smembers(f"morok:user_sessions:{PK}")}
    assert members == {_dg(legacy)}

    # повторний verify — уже по новій схемі
    assert (await ss.verify_session_token(redis, legacy)).pubkey_hex == PK


async def test_revoke_single_both_generations(redis):
    s = await ss.create_session(redis, PK)
    assert await ss.revoke_session(redis, s.token) is True
    assert await ss.verify_session_token(redis, s.token) is None

    legacy = ss.generate_token()
    await redis.set(f"morok:session:{legacy}", PK.encode(), ex=3600)
    await redis.sadd(f"morok:user_sessions:{PK}", legacy.encode())
    assert await ss.revoke_session(redis, legacy) is True
    assert await ss.verify_session_token(redis, legacy) is None


async def test_revoke_all_mixed_generations(redis):
    """logout-everywhere зносить і digest-, і plaintext-сесії."""
    pk = "ee" * 32
    fresh = await ss.create_session(redis, pk)
    legacy = ss.generate_token()
    await redis.set(f"morok:session:{legacy}", pk.encode(), ex=3600)
    await redis.sadd(f"morok:user_sessions:{pk}", legacy.encode())

    n = await ss.revoke_all_sessions(redis, pk)
    assert n == 2
    assert await ss.verify_session_token(redis, fresh.token) is None
    assert await ss.verify_session_token(redis, legacy) is None


async def test_revoke_publishes_ws_kill_event(redis):
    """
    Контракт «revoke закриває живий сокет»: подія session_revoked
    приходить у inbox-канал користувача з token_hash САМЕ цієї сесії
    (щоб інші пристрої не відвалились), а revoke_all — з token_hash=None
    (закрити все). inbox.py порівнює sha256 свого токена з token_hash.
    """
    pk = "dd" * 32
    s1 = await ss.create_session(redis, pk)
    s2 = await ss.create_session(redis, pk)

    ch = redis.pubsub()
    await ch.subscribe(f"morok:inbox:channel:{pk}")
    await asyncio.sleep(0.2)

    await ss.revoke_session(redis, s1.token)
    msg = await _next_event(ch)
    assert msg is not None
    event = json.loads(msg["data"])
    assert event["kind"] == "session_revoked"
    assert event["token_hash"] == _dg(s1.token)  # адресний kill: лише s1

    # s2 живе далі
    assert (await ss.verify_session_token(redis, s2.token)) is not None

    await ss.revoke_all_sessions(redis, pk)
    msg = await _next_event(ch)
    assert msg is not None
    event = json.loads(msg["data"])
    assert event["kind"] == "session_revoked"
    assert event["token_hash"] is None  # закрити ВСІ сокети

    await ch.aclose()


async def test_reverse_index_survives_as_long_as_session(redis):
    """
    Reverse-індекс мусить жити ≥ найдовшої сесії. Стара помилка: forward
    ковзав при кожному verify, а reverse протухав через 8 днів без
    освіження — і revoke_all (logout-everywhere, delete /me) бачив
    порожньо, лишаючи живі сесії видаленого акаунта.
    """
    s = await ss.create_session(redis, "cc" * 32)
    rk = f"morok:user_sessions:{'cc' * 32}"
    ttl_created = await redis.ttl(rk)
    assert ttl_created > ss.SESSION_ABSOLUTE_MAX_SECONDS, \
        "reverse коротший за стелю сесії — revoke_all осліпне"

    # verify освіжає reverse так само, як forward
    await redis.expire(rk, 100)
    assert await ss.verify_session_token(redis, s.token) is not None
    assert await redis.ttl(rk) > ss.SESSION_ABSOLUTE_MAX_SECONDS

    # і revoke_all після цього справді бачить сесію
    revoked = await ss.revoke_all_sessions(redis, "cc" * 32)
    assert revoked == 1
    assert await ss.verify_session_token(redis, s.token) is None
