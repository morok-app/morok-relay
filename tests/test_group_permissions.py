"""
Групи: логіка прав (`api/groups.py`, 1622 рядки — досі без покриття).

Це найгустіше місце з перевірками доступу в усьому релеї, і саме воно
не покривалось жодним тестом. Фіксуємо контракт ДО того, як розбивати
файл на частини і чіпати `selectinload` (MEDIUM-1 з аудиту 4) — інакше
рефакторинг робиться наосліп.

Особлива увага мульти-адмінському випадку: у коді є явне попередження,
що патерн `_find_admin().pubkey == caller` мовчки блокує всіх адмінів,
крім першого у списку. Тест фіксує правильну поведінку, щоб цей баг не
повернувся.
"""
from __future__ import annotations

import time
import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from morok_relay.api.groups import (
    _find_admin,
    _is_admin,
    _is_member,
    _parse_group_id,
    add_member,
    remove_member,
)
from morok_relay.models import Group, GroupMember

pytestmark = pytest.mark.asyncio

CREATOR = bytes.fromhex("11" * 32)
ADMIN2 = bytes.fromhex("22" * 32)
MEMBER = bytes.fromhex("33" * 32)
OUTSIDER = bytes.fromhex("44" * 32)
NEWBIE = bytes.fromhex("55" * 32)


def _group(members: list[tuple[bytes, bool]], max_members: int = 50) -> Group:
    """members: список (pubkey, is_admin). Перший — творець."""
    now = int(time.time())
    g = Group(
        id=uuid.uuid4(),
        creator_pubkey=members[0][0],
        name_encrypted=b"\x01" * 32,
        is_channel=False,
        default_ttl_seconds=86400,
        anonymous_senders=False,
        max_members=max_members,
        created_at=now,
    )
    for pk, is_admin in members:
        g.members.append(GroupMember(
            id=uuid.uuid4(), pubkey=pk, is_admin=is_admin, joined_at=now,
        ))
    return g


async def _persist(db, group: Group) -> Group:
    db.add(group)
    await db.commit()
    return group


class _Session:
    """Мінімальний CurrentSession."""

    def __init__(self, pubkey: bytes):
        self.pubkey_hex = pubkey.hex()
        self.token = "t" * 64
        self.expires_at = 2 ** 31


# ── чисті хелпери прав ───────────────────────────────────────────────────
async def test_is_member_basic():
    g = _group([(CREATOR, True), (MEMBER, False)])
    assert _is_member(g, CREATOR)
    assert _is_member(g, MEMBER)
    assert not _is_member(g, OUTSIDER)


async def test_is_admin_recognises_every_admin_not_just_first():
    """
    РЕГРЕСІЯ НА ТОНКИЙ БАГ. `_find_admin()` повертає ЛИШЕ першого адміна;
    якщо авторизацію писати як `_find_admin().pubkey == caller`, кожен
    адмін, крім першого у списку, мовчки втрачає права.
    """
    g = _group([(CREATOR, True), (ADMIN2, True), (MEMBER, False)])

    assert _is_admin(g, CREATOR)
    assert _is_admin(g, ADMIN2), "другий адмін втратив права"
    assert not _is_admin(g, MEMBER)
    assert not _is_admin(g, OUTSIDER)

    # саме та пастка, від якої застерігає докстрінг
    first = _find_admin(g)
    assert first is not None
    assert first.pubkey == CREATOR
    assert first.pubkey != ADMIN2


async def test_is_admin_false_for_member_who_is_not_admin():
    g = _group([(CREATOR, True), (MEMBER, False)])
    assert not _is_admin(g, MEMBER)


async def test_find_admin_returns_none_when_no_admins():
    g = _group([(MEMBER, False)])
    assert _find_admin(g) is None
    assert not _is_admin(g, MEMBER)


async def test_parse_group_id_rejects_garbage():
    with pytest.raises(HTTPException) as e:
        _parse_group_id("not-a-uuid")
    assert e.value.status_code == 400


# ── add_member ───────────────────────────────────────────────────────────
async def test_add_member_requires_admin(db):
    g = await _persist(db, _group([(CREATOR, True), (MEMBER, False)]))

    class Body:
        pubkey_hex = NEWBIE.hex()

    with pytest.raises(HTTPException) as e:
        await add_member(str(g.id), Body(), _Session(MEMBER), db)
    assert e.value.status_code == 403
    assert e.value.detail == "only_admin_can_add_members"


async def test_add_member_second_admin_allowed(db):
    """Другий адмін мусить мати ті самі права, що й перший."""
    g = await _persist(db, _group([(CREATOR, True), (ADMIN2, True)]))

    class Body:
        pubkey_hex = NEWBIE.hex()

    res = await add_member(str(g.id), Body(), _Session(ADMIN2), db)
    assert res.member_count == 3


async def test_add_member_is_idempotent(db):
    """Повторне додавання наявного члена не двоїть його."""
    g = await _persist(db, _group([(CREATOR, True), (MEMBER, False)]))

    class Body:
        pubkey_hex = MEMBER.hex()

    res = await add_member(str(g.id), Body(), _Session(CREATOR), db)
    assert res.member_count == 2

    rows = (await db.execute(
        select(GroupMember).where(GroupMember.group_id == g.id)
    )).scalars().all()
    assert len(rows) == 2


async def test_add_member_respects_max_members(db):
    g = await _persist(db, _group([(CREATOR, True), (MEMBER, False)], max_members=2))

    class Body:
        pubkey_hex = NEWBIE.hex()

    with pytest.raises(HTTPException) as e:
        await add_member(str(g.id), Body(), _Session(CREATOR), db)
    assert e.value.status_code == 409
    assert "group_full" in e.value.detail


async def test_add_member_outsider_rejected(db):
    g = await _persist(db, _group([(CREATOR, True)]))

    class Body:
        pubkey_hex = NEWBIE.hex()

    with pytest.raises(HTTPException) as e:
        await add_member(str(g.id), Body(), _Session(OUTSIDER), db)
    assert e.value.status_code == 403


# ── remove_member ────────────────────────────────────────────────────────
async def test_member_can_remove_self(db):
    g = await _persist(db, _group([(CREATOR, True), (MEMBER, False)]))
    res = await remove_member(str(g.id), MEMBER.hex(), _Session(MEMBER), db)
    assert res.action == "removed"
    assert res.member_count == 1


async def test_member_cannot_remove_others(db):
    g = await _persist(db, _group([
        (CREATOR, True), (MEMBER, False), (OUTSIDER, False),
    ]))
    with pytest.raises(HTTPException) as e:
        await remove_member(str(g.id), OUTSIDER.hex(), _Session(MEMBER), db)
    assert e.value.status_code == 403
    assert e.value.detail == "must_be_self_or_admin"


async def test_admin_can_remove_member(db):
    g = await _persist(db, _group([(CREATOR, True), (MEMBER, False)]))
    res = await remove_member(str(g.id), MEMBER.hex(), _Session(CREATOR), db)
    assert res.member_count == 1


async def test_second_admin_can_remove_member(db):
    g = await _persist(db, _group([
        (CREATOR, True), (ADMIN2, True), (MEMBER, False),
    ]))
    res = await remove_member(str(g.id), MEMBER.hex(), _Session(ADMIN2), db)
    assert res.member_count == 2


async def test_creator_cannot_leave(db):
    """Творець не може вийти — тільки видалити групу (інакше сирота)."""
    g = await _persist(db, _group([(CREATOR, True), (MEMBER, False)]))
    with pytest.raises(HTTPException) as e:
        await remove_member(str(g.id), CREATOR.hex(), _Session(CREATOR), db)
    assert e.value.status_code == 409
    assert e.value.detail == "creator_cannot_leave_must_delete_group"


async def test_admin_cannot_remove_creator(db):
    """Навіть інший адмін не може викинути творця."""
    g = await _persist(db, _group([(CREATOR, True), (ADMIN2, True)]))
    with pytest.raises(HTTPException) as e:
        await remove_member(str(g.id), CREATOR.hex(), _Session(ADMIN2), db)
    assert e.value.status_code == 409


async def test_remove_non_member_404(db):
    g = await _persist(db, _group([(CREATOR, True)]))
    with pytest.raises(HTTPException) as e:
        await remove_member(str(g.id), OUTSIDER.hex(), _Session(CREATOR), db)
    assert e.value.status_code == 404
    assert e.value.detail == "not_a_member"


async def test_remove_member_malformed_pubkey(db):
    g = await _persist(db, _group([(CREATOR, True)]))
    for bad in ("xx", "zz" * 32, "11" * 31):
        with pytest.raises(HTTPException) as e:
            await remove_member(str(g.id), bad, _Session(CREATOR), db)
        assert e.value.status_code == 400
        assert e.value.detail == "malformed_pubkey"


async def test_deleted_group_is_404(db):
    """Група з deleted_at не вантажиться взагалі."""
    g = _group([(CREATOR, True)])
    g.deleted_at = int(time.time())
    await _persist(db, g)

    class Body:
        pubkey_hex = NEWBIE.hex()

    with pytest.raises(HTTPException) as e:
        await add_member(str(g.id), Body(), _Session(CREATOR), db)
    assert e.value.status_code == 404
