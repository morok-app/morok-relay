"""
Жорсткі межі протоколу на group snapshot (аудит зовн. №4, MEDIUM).

Знахідка: apply_group_snapshot довіряв структурі payload'а майже без
перевірки — max_members міг бути будь-яким int (0, від'ємне, мільйон),
members міг бути списком БУДЬ-ЯКОЇ довжини, pubkey_hex приймався будь-
якої парної довжини (bytes.fromhex не перевіряє розмір; GroupMember.
pubkey у Postgres — bytea без CHECK-обмеження, LargeBinary(32) у
SQLAlchemy лише hint). "Trusted peer" (сигнатура/TLS валідні) не
означає "peer не зламаний і не має багів" — це containment, не
auth-обхід.
"""
from __future__ import annotations

import base64
import time
import uuid

import pytest
from fastapi import HTTPException

from morok_relay.api.groups import PREMIUM_TIER_MAX_MEMBERS, apply_group_snapshot

pytestmark = pytest.mark.asyncio

HOST = "relay1.morok.app"
CREATOR = "11" * 32


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


# ── max_members bounds ───────────────────────────────────────────────────
async def test_max_members_zero_rejected(db):
    gid = str(uuid.uuid4())
    with pytest.raises(HTTPException) as e:
        await apply_group_snapshot(
            db, _snapshot(gid, [(CREATOR, True)], max_members=0),
            expected_home_relay=HOST,
        )
    assert e.value.status_code == 400


async def test_max_members_negative_rejected(db):
    gid = str(uuid.uuid4())
    with pytest.raises(HTTPException):
        await apply_group_snapshot(
            db, _snapshot(gid, [(CREATOR, True)], max_members=-5),
            expected_home_relay=HOST,
        )


async def test_max_members_absurdly_large_rejected(db):
    """ГОЛОВНИЙ СЦЕНАРІЙ з аудиту: скомпрометований peer намагається
    засунути max_members=100000."""
    gid = str(uuid.uuid4())
    with pytest.raises(HTTPException) as e:
        await apply_group_snapshot(
            db, _snapshot(gid, [(CREATOR, True)], max_members=100_000),
            expected_home_relay=HOST,
        )
    assert "max_members" in e.value.detail


async def test_max_members_at_protocol_ceiling_allowed(db):
    """Стеля протоколу (PREMIUM_TIER_MAX_MEMBERS) — легітимне значення,
    не має відхилятись."""
    gid = str(uuid.uuid4())
    group = await apply_group_snapshot(
        db, _snapshot(gid, [(CREATOR, True)],
                      max_members=PREMIUM_TIER_MAX_MEMBERS),
        expected_home_relay=HOST,
    )
    assert group.max_members == PREMIUM_TIER_MAX_MEMBERS


# ── members list length bound ────────────────────────────────────────────
async def test_oversized_members_list_rejected(db):
    """
    Список members довший за протокольну стелю — відмова ДО будь-якої
    вставки в БД (не намагаємось вставити частину й впасти посередині).
    """
    gid = str(uuid.uuid4())
    huge = [(f"{i:064x}", False) for i in range(PREMIUM_TIER_MAX_MEMBERS + 1)]
    with pytest.raises(HTTPException) as e:
        await apply_group_snapshot(
            db, _snapshot(gid, huge, max_members=PREMIUM_TIER_MAX_MEMBERS),
            expected_home_relay=HOST,
        )
    assert "members list" in e.value.detail


async def test_members_not_a_list_rejected(db):
    gid = str(uuid.uuid4())
    snap = _snapshot(gid, [(CREATOR, True)])
    snap["members"] = "not-a-list"
    with pytest.raises(HTTPException):
        await apply_group_snapshot(db, snap, expected_home_relay=HOST)


# ── pubkey length: рівно 32 байти, не "будь-яка парна довжина" ──────────
async def test_undersized_pubkey_silently_dropped_not_inserted(db):
    """
    ГОЛОВНИЙ ТЕСТ. bytes.fromhex приймає БУДЬ-ЯКУ парну кількість
    символів — без явної перевірки довжини кривий 1-байтовий "pubkey"
    потрапив би в GroupMember.pubkey (bytea без CHECK). Тепер такий
    запис просто відкидається (як і раніше кривий hex), решта
    snapshot обробляється нормально.
    """
    gid = str(uuid.uuid4())
    snap = _snapshot(gid, [(CREATOR, True)])
    snap["members"].append({"pubkey_hex": "aa", "is_admin": False})  # 1 байт
    group = await apply_group_snapshot(db, snap, expected_home_relay=HOST)
    pks = {m.pubkey.hex() for m in group.members}
    assert pks == {CREATOR}, "1-байтовий pubkey не мав потрапити в БД"


async def test_oversized_pubkey_silently_dropped(db):
    gid = str(uuid.uuid4())
    snap = _snapshot(gid, [(CREATOR, True)])
    snap["members"].append({"pubkey_hex": "bb" * 100, "is_admin": False})
    group = await apply_group_snapshot(db, snap, expected_home_relay=HOST)
    pks = {m.pubkey.hex() for m in group.members}
    assert pks == {CREATOR}


async def test_exactly_32_bytes_pubkey_accepted(db):
    gid = str(uuid.uuid4())
    valid_member = "cc" * 32
    group = await apply_group_snapshot(
        db, _snapshot(gid, [(CREATOR, True), (valid_member, False)]),
        expected_home_relay=HOST,
    )
    pks = {m.pubkey.hex() for m in group.members}
    assert valid_member in pks


async def test_non_dict_member_entries_skipped(db):
    gid = str(uuid.uuid4())
    snap = _snapshot(gid, [(CREATOR, True)])
    snap["members"].extend(["not-a-dict", 12345, None])
    group = await apply_group_snapshot(db, snap, expected_home_relay=HOST)
    pks = {m.pubkey.hex() for m in group.members}
    assert pks == {CREATOR}


# ── name_encrypted та ttl bounds ─────────────────────────────────────────
async def test_oversized_name_rejected(db):
    from morok_relay.api.groups import GROUP_NAME_MAX_BYTES
    gid = str(uuid.uuid4())
    snap = _snapshot(gid, [(CREATOR, True)])
    snap["name_encrypted_b64"] = base64.b64encode(
        b"\x01" * (GROUP_NAME_MAX_BYTES + 1)
    ).decode()
    with pytest.raises(HTTPException):
        await apply_group_snapshot(db, snap, expected_home_relay=HOST)


async def test_ttl_zero_rejected(db):
    gid = str(uuid.uuid4())
    with pytest.raises(HTTPException):
        await apply_group_snapshot(
            db, _snapshot(gid, [(CREATOR, True)], default_ttl_seconds=0),
            expected_home_relay=HOST,
        )


async def test_ttl_absurdly_large_rejected(db):
    gid = str(uuid.uuid4())
    with pytest.raises(HTTPException):
        await apply_group_snapshot(
            db, _snapshot(gid, [(CREATOR, True)],
                          default_ttl_seconds=999 * 86400),
            expected_home_relay=HOST,
        )


async def test_creator_pubkey_wrong_length_rejected(db):
    gid = str(uuid.uuid4())
    snap = _snapshot(gid, [(CREATOR, True)])
    snap["creator_pubkey_hex"] = "aa"  # не 64 символи
    with pytest.raises(HTTPException):
        await apply_group_snapshot(db, snap, expected_home_relay=HOST)


# ── легітимний шлях досі працює ──────────────────────────────────────────
async def test_normal_snapshot_still_works(db):
    gid = str(uuid.uuid4())
    group = await apply_group_snapshot(
        db, _snapshot(gid, [(CREATOR, True), ("dd" * 32, False)]),
        expected_home_relay=HOST,
    )
    assert len(group.members) == 2
    assert group.max_members == 50
