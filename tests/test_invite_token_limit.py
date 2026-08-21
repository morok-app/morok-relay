"""
Group invite tokens: атомарний ліміт активних токенів (жорсткий свіжий
прохід — знайдено одразу після ідентичної проблеми в burner_tokens.py,
тим самим часом). Той самий клас check-then-insert race:
count_active_tokens() (читання) і create_token() (запис) були
окремими операціями.
"""
from __future__ import annotations

import asyncio

import pytest

from morok_relay import invite_tokens as it

pytestmark = pytest.mark.asyncio

GROUP_ID = "11111111-2222-3333-4444-555555555555"
ADMIN = "aa" * 32


async def test_create_token_succeeds_under_limit(redis):
    info = await it.create_token(redis, GROUP_ID, ADMIN)
    assert info is not None
    assert "token" in info


async def test_create_token_returns_none_at_limit(redis):
    for _ in range(it.MAX_ACTIVE_TOKENS_PER_GROUP):
        assert await it.create_token(redis, GROUP_ID, ADMIN) is not None
    assert await it.create_token(redis, GROUP_ID, ADMIN) is None


async def test_revoke_frees_a_slot(redis):
    infos = [await it.create_token(redis, GROUP_ID, ADMIN)
             for _ in range(it.MAX_ACTIVE_TOKENS_PER_GROUP)]
    assert await it.create_token(redis, GROUP_ID, ADMIN) is None

    await it.revoke_token(redis, GROUP_ID, infos[0]["token"])
    assert await it.create_token(redis, GROUP_ID, ADMIN) is not None


async def test_expired_token_in_set_does_not_block_new_creation(redis):
    """Stale-члени SET (протухлі ключі) не мають блокувати нове
    створення — той самий нюанс, що в burner_tokens.py."""
    group_key = it._group_invites_key(GROUP_ID)
    for i in range(it.MAX_ACTIVE_TOKENS_PER_GROUP):
        await redis.sadd(group_key, f"stale-invite-{i}")

    result = await it.create_token(redis, GROUP_ID, ADMIN)
    assert result is not None, \
        "відмова через застарілі (протухлі) записи в group-SET"


async def test_concurrent_create_never_exceeds_limit(redis):
    """
    ГОЛОВНИЙ ТЕСТ атомарності. Ліміт майже вичерпаний, десять
    паралельних create_token на останнє вільне місце — атомарно має
    пройти рівно один. Redis EVAL сам по собі однопотоковий на
    сервері.
    """
    for _ in range(it.MAX_ACTIVE_TOKENS_PER_GROUP - 1):
        await it.create_token(redis, GROUP_ID, ADMIN)

    results = await asyncio.gather(
        *[it.create_token(redis, GROUP_ID, ADMIN) for _ in range(10)]
    )
    succeeded = [r for r in results if r is not None]
    assert len(succeeded) == 1, \
        f"прийнято {len(succeeded)} нових токенів замість рівно 1"

    active = await it.count_active_tokens(redis, GROUP_ID)
    assert active == it.MAX_ACTIVE_TOKENS_PER_GROUP


# ── наскрізно через API-ендпоінт ──────────────────────────────────────────
async def test_endpoint_returns_409_at_limit(db, redis):
    import time
    import uuid

    from fastapi import HTTPException

    from morok_relay.api.groups import create_invite_token
    from morok_relay.models import Group, GroupMember
    from morok_relay.schemas import InviteTokenCreate
    from morok_relay.sessions import Session

    now = int(time.time())
    gid = uuid.uuid4()
    admin_pk = bytes.fromhex(ADMIN)
    group = Group(
        id=gid, creator_pubkey=admin_pk, name_encrypted=b"\x01" * 32,
        is_channel=False, default_ttl_seconds=86400,
        anonymous_senders=False, max_members=50, created_at=now,
    )
    group.members.append(GroupMember(
        id=uuid.uuid4(), pubkey=admin_pk, is_admin=True, joined_at=now,
    ))
    db.add(group)
    await db.commit()

    session = Session(token="t" * 64, pubkey_hex=ADMIN, expires_at=2**31)
    for _ in range(it.MAX_ACTIVE_TOKENS_PER_GROUP):
        await create_invite_token(
            str(gid), InviteTokenCreate(), session, db, redis,
        )

    with pytest.raises(HTTPException) as e:
        await create_invite_token(
            str(gid), InviteTokenCreate(), session, db, redis,
        )
    assert e.value.status_code == 409
    assert "too_many_active_invites" in e.value.detail
