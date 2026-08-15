"""
Аудит 5 (повний прохід): адмін-токени й invite-сети.

  * Адмін-токен у Redis лежить лише як SHA-256 — компрометація Redis
    не віддає живий токен адмінки (той самий принцип, що для сесій).
  * Сет morok:group_invites:{gid} має TTL — інакше жив вічно і
    volatile-ttl не мав що витісняти (сімейство inbox-ключів).
"""
from __future__ import annotations

import hashlib

import pytest

from morok_relay import invite_tokens as it
from morok_relay.api.admin import _create_admin_token, _verify_admin_token

pytestmark = pytest.mark.asyncio


async def test_admin_token_stored_as_digest_only(redis):
    token = await _create_admin_token(redis, ttl_seconds=3600)

    digest = hashlib.sha256(token.encode()).hexdigest()
    assert await redis.exists(f"morok:admin_session:{digest}")
    assert not await redis.exists(f"morok:admin_session:{token}"), \
        "адмін-токен у Redis відкритим текстом"

    assert await _verify_admin_token(redis, token) is True
    assert await _verify_admin_token(redis, "wrong-token") is False
    assert await _verify_admin_token(redis, "") is False


async def test_invite_set_has_ttl(redis):
    await it.create_token(redis, "gid-1", "aa" * 32, ttl_seconds=3600)
    ttl = await redis.ttl("morok:group_invites:gid-1")
    assert ttl > 0, "сет запрошень без TTL — жив би вічно"
    assert ttl > it.MAX_TTL_SECONDS, "TTL сета коротший за найдовший токен"


async def test_invite_set_ttl_slides_forward(redis):
    await it.create_token(redis, "gid-2", "aa" * 32, ttl_seconds=3600)
    await redis.expire("morok:group_invites:gid-2", 100)
    await it.create_token(redis, "gid-2", "aa" * 32, ttl_seconds=3600)
    assert await redis.ttl("morok:group_invites:gid-2") > 1000
