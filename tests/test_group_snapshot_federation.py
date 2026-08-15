"""
Федерація: прийом snapshot'а групи від peer-релея (`apply_group_snapshot`).

Це найгостріша межа довіри в усьому релеї: чужий сервер надсилає стан
групи, і ми його застосовуємо. Два зловживання, які тут блокуються:

  * довірений peer X пушить snapshot групи, чий справжній host — Y
    (спроба переписати склад чужої групи);
  * peer X створює нову групу з `home_relay=Y` у payload'і — тобто
    підсаджує в мережу групу з чужим іменем господаря.

Друге лікується тим, що поле `home_relay` з payload'а ІГНОРУЄТЬСЯ, а
записується перевірений відправник. Тести фіксують обидва інваріанти —
і те, що знесення членів працює тільки для справжнього господаря.

Файл не мав покриття взагалі; логіка перевірялась лише читанням.
"""
from __future__ import annotations

import base64
import time
import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from morok_relay.api.groups import apply_group_snapshot
from morok_relay.models import Group, GroupMember

pytestmark = pytest.mark.asyncio

HOST = "relay1.morok.app"
EVIL = "evil.example.com"

CREATOR = "11" * 32
MEMBER_A = "22" * 32
MEMBER_B = "33" * 32


def _snapshot(gid: str, members: list[tuple[str, bool]], **over) -> dict:
    snap = {
        "group_id": gid,
        "creator_pubkey_hex": CREATOR,
        "name_encrypted_b64": base64.b64encode(b"\x01" * 32).decode(),
        "is_channel": False,
        "default_ttl_seconds": 86400,
        "anonymous_senders": False,
        "max_members": 50,
        "members": [
            {"pubkey_hex": pk, "is_admin": adm, "joined_at": int(time.time())}
            for pk, adm in members
        ],
    }
    snap.update(over)
    return snap


async def _load(db, gid) -> Group | None:
    return (await db.execute(
        select(Group).options(selectinload(Group.members))
        .where(Group.id == uuid.UUID(str(gid)))
    )).scalar_one_or_none()


# ── створення ────────────────────────────────────────────────────────────
async def test_new_group_created_from_snapshot(db):
    gid = str(uuid.uuid4())
    snap = _snapshot(gid, [(CREATOR, True), (MEMBER_A, False)])

    group = await apply_group_snapshot(db, snap, expected_home_relay=HOST)
    await db.commit()

    assert str(group.id) == gid
    assert group.home_relay == HOST
    assert len(group.members) == 2


async def test_home_relay_from_payload_is_ignored(db):
    """
    КЛЮЧОВИЙ ІНВАРІАНТ. Peer каже «ця група хоститься на relay1», хоча
    сам він evil.example.com. Ми записуємо ВІДПРАВНИКА, не payload —
    інакше зловмисний peer підсаджував би в мережу групи з чужим
    іменем господаря.
    """
    gid = str(uuid.uuid4())
    snap = _snapshot(gid, [(CREATOR, True)], home_relay=HOST)

    group = await apply_group_snapshot(db, snap, expected_home_relay=EVIL)
    await db.commit()

    assert group.home_relay == EVIL, "home_relay взято з payload'а — діра"


async def test_missing_expected_home_relay_rejected(db):
    gid = str(uuid.uuid4())
    with pytest.raises(HTTPException) as e:
        await apply_group_snapshot(
            db, _snapshot(gid, [(CREATOR, True)]), expected_home_relay="",
        )
    assert e.value.status_code == 400


# ── межа довіри при оновленні ────────────────────────────────────────────
async def test_wrong_host_cannot_update_existing_group(db):
    """Довірений peer не може переписати групу, чий host — інший релей."""
    gid = str(uuid.uuid4())
    await apply_group_snapshot(
        db, _snapshot(gid, [(CREATOR, True), (MEMBER_A, False)]),
        expected_home_relay=HOST,
    )
    await db.commit()

    hostile = _snapshot(gid, [(CREATOR, True), (MEMBER_B, True)])
    with pytest.raises(HTTPException) as e:
        await apply_group_snapshot(db, hostile, expected_home_relay=EVIL)
    assert e.value.status_code == 403
    assert "wrong_host" in e.value.detail

    await db.rollback()
    group = await _load(db, gid)
    pks = {m.pubkey.hex() for m in group.members}
    assert pks == {CREATOR, MEMBER_A}, "склад групи змінено чужим релеєм"


async def test_real_host_can_update(db):
    gid = str(uuid.uuid4())
    await apply_group_snapshot(
        db, _snapshot(gid, [(CREATOR, True)]), expected_home_relay=HOST,
    )
    await db.commit()

    await apply_group_snapshot(
        db, _snapshot(gid, [(CREATOR, True), (MEMBER_A, False)]),
        expected_home_relay=HOST,
    )
    await db.commit()

    group = await _load(db, gid)
    assert len(group.members) == 2


async def test_legacy_null_home_relay_adopted_by_first_pusher(db):
    """Старі рядки без home_relay усиновлює перший, хто запушив."""
    gid = uuid.uuid4()
    g = Group(
        id=gid, creator_pubkey=bytes.fromhex(CREATOR),
        name_encrypted=b"\x01" * 32, is_channel=False,
        default_ttl_seconds=86400, anonymous_senders=False,
        max_members=50, created_at=int(time.time()), home_relay=None,
    )
    db.add(g)
    await db.commit()

    group = await apply_group_snapshot(
        db, _snapshot(str(gid), [(CREATOR, True)]), expected_home_relay=HOST,
    )
    await db.commit()
    assert group.home_relay == HOST

    # далі вже діє звичайна межа
    with pytest.raises(HTTPException):
        await apply_group_snapshot(
            db, _snapshot(str(gid), [(CREATOR, True)]),
            expected_home_relay=EVIL,
        )


# ── звірка складу ────────────────────────────────────────────────────────
async def test_members_removed_when_absent_from_snapshot(db):
    """Snapshot авторитетний: кого немає — того видаляємо."""
    gid = str(uuid.uuid4())
    await apply_group_snapshot(
        db, _snapshot(gid, [(CREATOR, True), (MEMBER_A, False), (MEMBER_B, False)]),
        expected_home_relay=HOST,
    )
    await db.commit()

    await apply_group_snapshot(
        db, _snapshot(gid, [(CREATOR, True), (MEMBER_B, False)]),
        expected_home_relay=HOST,
    )
    await db.commit()

    group = await _load(db, gid)
    pks = {m.pubkey.hex() for m in group.members}
    assert pks == {CREATOR, MEMBER_B}


async def test_admin_flag_updated_in_place(db):
    gid = str(uuid.uuid4())
    await apply_group_snapshot(
        db, _snapshot(gid, [(CREATOR, True), (MEMBER_A, False)]),
        expected_home_relay=HOST,
    )
    await db.commit()

    await apply_group_snapshot(
        db, _snapshot(gid, [(CREATOR, True), (MEMBER_A, True)]),
        expected_home_relay=HOST,
    )
    await db.commit()

    rows = (await db.execute(
        select(GroupMember).where(
            GroupMember.group_id == uuid.UUID(gid),
            GroupMember.pubkey == bytes.fromhex(MEMBER_A),
        )
    )).scalars().all()
    assert len(rows) == 1 and rows[0].is_admin is True


async def test_apply_is_idempotent(db):
    gid = str(uuid.uuid4())
    snap = _snapshot(gid, [(CREATOR, True), (MEMBER_A, False)])
    for _ in range(3):
        await apply_group_snapshot(db, snap, expected_home_relay=HOST)
        await db.commit()

    group = await _load(db, gid)
    assert len(group.members) == 2


# ── стійкість до сміття ──────────────────────────────────────────────────
async def test_malformed_snapshot_rejected(db):
    gid = str(uuid.uuid4())
    for broken in (
        {"group_id": "not-a-uuid", "creator_pubkey_hex": CREATOR,
         "name_encrypted_b64": "AAAA"},
        {"group_id": gid, "creator_pubkey_hex": "zz",
         "name_encrypted_b64": "AAAA"},
        {"group_id": gid, "creator_pubkey_hex": CREATOR,
         "name_encrypted_b64": "!!!not-base64!!!"},
        {"creator_pubkey_hex": CREATOR, "name_encrypted_b64": "AAAA"},
    ):
        with pytest.raises(HTTPException) as e:
            await apply_group_snapshot(db, broken, expected_home_relay=HOST)
        assert e.value.status_code == 400


async def test_garbage_member_entries_skipped_not_fatal(db):
    """Кривий член у списку не має валити весь snapshot."""
    gid = str(uuid.uuid4())
    snap = _snapshot(gid, [(CREATOR, True)])
    snap["members"].extend([
        {"pubkey_hex": "zz"},          # не hex
        {"is_admin": True},            # без ключа
        {"pubkey_hex": MEMBER_A, "is_admin": False},  # валідний
    ])

    group = await apply_group_snapshot(db, snap, expected_home_relay=HOST)
    await db.commit()

    pks = {m.pubkey.hex() for m in group.members}
    assert pks == {CREATOR, MEMBER_A}
