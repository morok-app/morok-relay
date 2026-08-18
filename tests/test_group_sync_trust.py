"""
/groups/{id}/sync: клієнт міг призначити довільний "авторитетний" host
(аудит зовн. №3, HIGH — найнебезпечніша знахідка цього проходу).

Ланцюжок атаки, який тут закривається:
  1. Клієнт викликає sync?host_relay=attacker.example.com — довільний
     публічний домен, під контролем зловмисника (pin-to-IP і SSRF-guard
     тут НЕ допоможуть: attacker.example.com — легітимний публічний
     сервер, просто не наш федеративний peer).
  2. Наш relay підписаним запитом стукає туди (remote_pull_group_
     snapshot) — сервер attacker'а відповідає ДОВІЛЬНИМ JSON, що
     виглядає як valid snapshot.
  3. apply_group_snapshot(..., expected_home_relay=host_relay) приймає
     host_relay як довірений — якщо групи ще нема локально, вона
     СТВОРЮЄТЬСЯ з вигаданим складом і home_relay=домен атакуючого.

Фікс: host_relay мусить бути відомим TRUSTED peer (та сама межа
довіри, що і для будь-якого іншого federation write-шляху). Другий
незалежний шар: snapshot["group_id"] у відповіді мусить збігатися з
group_id з URL — інакше зловмисний/збитий host міг би тихо підмінити
ЗОВСІМ ІНШУ локальну групу.
"""
from __future__ import annotations

import time
import uuid

import pytest
from fastapi import HTTPException

from morok_relay.api.groups import sync_group_from_host
from morok_relay.config import get_settings
from morok_relay.models import FederationPeer
from morok_relay.sessions import Session

pytestmark = pytest.mark.asyncio

CALLER = "aa" * 32
ATTACKER_HOST = "attacker.example.com"
TRUSTED_HOST = "relay2.example.com"


def _session() -> Session:
    return Session(token="t" * 64, pubkey_hex=CALLER, expires_at=2**31)


async def _add_peer(db, hostname: str, *, trusted: bool) -> None:
    db.add(FederationPeer(
        id=uuid.uuid4(), hostname=hostname, pubkey=b"\x01" * 32,
        is_trusted=trusted, created_at=int(time.time()),
    ))
    await db.commit()


# ── ГОЛОВНИЙ ТЕСТ: невідомий host відмовляється ДО будь-якого мережевого виклику ──
async def test_unknown_host_rejected_before_network_call(db, redis, monkeypatch):
    """
    host_relay, якого немає в federation_peers взагалі — 403, і
    remote_pull_group_snapshot НЕ МАЄ навіть викликатись (перевіряємо
    явно: якби мережевий виклик стався, це вже саме по собі означало б,
    що дефолтний-довірений режим не спрацював).
    """
    called = {"n": 0}

    async def spy_pull(*a, **kw):
        called["n"] += 1
        return {"group_id": str(uuid.uuid4()), "members": []}

    monkeypatch.setattr(
        "morok_relay.federation_client.remote_pull_group_snapshot", spy_pull,
    )

    with pytest.raises(HTTPException) as e:
        await sync_group_from_host(
            str(uuid.uuid4()), _session(), db, redis,
            host_relay=ATTACKER_HOST,
        )
    assert e.value.status_code == 403
    assert e.value.detail == "host_relay_not_a_trusted_peer"
    assert called["n"] == 0, "мережевий виклик стався ДО перевірки довіри"


async def test_untrusted_but_known_peer_rejected(db, redis):
    """
    Peer існує (пройшов handshake колись), але is_trusted=False —
    той самий бар'єр, що і для forward/pull на стороні host. Половинчаста
    довіра (handshake without explicit trust) не має відкривати sync.
    """
    await _add_peer(db, ATTACKER_HOST, trusted=False)
    with pytest.raises(HTTPException) as e:
        await sync_group_from_host(
            str(uuid.uuid4()), _session(), db, redis,
            host_relay=ATTACKER_HOST,
        )
    assert e.value.status_code == 403
    assert e.value.detail == "host_relay_not_a_trusted_peer"


async def test_trusted_peer_allowed_through_gate(db, redis, monkeypatch):
    """Довірений peer проходить gate і мережевий виклик відбувається."""
    await _add_peer(db, TRUSTED_HOST, trusted=True)
    gid = uuid.uuid4()

    async def fake_pull(*a, **kw):
        return {
            "group_id": str(gid),
            "creator_pubkey_hex": CALLER,
            "name_encrypted_b64": "AAAA",
            "is_channel": False,
            "default_ttl_seconds": 86400,
            "anonymous_senders": False,
            "max_members": 50,
            "members": [{"pubkey_hex": CALLER, "is_admin": True,
                        "joined_at": int(time.time())}],
        }
    monkeypatch.setattr(
        "morok_relay.federation_client.remote_pull_group_snapshot", fake_pull,
    )

    result = await sync_group_from_host(
        str(gid), _session(), db, redis, host_relay=TRUSTED_HOST,
    )
    assert result["synced"] is True
    assert result["host_relay"] == TRUSTED_HOST


# ── group_id binding: відповідь мусить бути про ТУ групу, яку просили ──
async def test_snapshot_for_different_group_id_rejected(db, redis, monkeypatch):
    """
    Host (чи MITM між нами й ним) повертає valid-looking snapshot, але
    для ІНШОГО group_id — не можна тихо застосувати його до групи, яку
    клієнт не просив.
    """
    await _add_peer(db, TRUSTED_HOST, trusted=True)
    requested_gid = uuid.uuid4()
    different_gid = uuid.uuid4()

    async def fake_pull(*a, **kw):
        return {
            "group_id": str(different_gid),  # НЕ те, що попросили
            "creator_pubkey_hex": CALLER,
            "name_encrypted_b64": "AAAA",
            "is_channel": False,
            "default_ttl_seconds": 86400,
            "anonymous_senders": False,
            "max_members": 50,
            "members": [],
        }
    monkeypatch.setattr(
        "morok_relay.federation_client.remote_pull_group_snapshot", fake_pull,
    )

    with pytest.raises(HTTPException) as e:
        await sync_group_from_host(
            str(requested_gid), _session(), db, redis, host_relay=TRUSTED_HOST,
        )
    assert e.value.status_code == 502
    assert e.value.detail == "host_returned_snapshot_for_different_group"


async def test_snapshot_with_malformed_group_id_rejected(db, redis, monkeypatch):
    await _add_peer(db, TRUSTED_HOST, trusted=True)
    gid = uuid.uuid4()

    async def fake_pull(*a, **kw):
        return {"group_id": "not-a-uuid", "members": []}
    monkeypatch.setattr(
        "morok_relay.federation_client.remote_pull_group_snapshot", fake_pull,
    )

    with pytest.raises(HTTPException) as e:
        await sync_group_from_host(
            str(gid), _session(), db, redis, host_relay=TRUSTED_HOST,
        )
    assert e.value.status_code == 502


# ── існуючі перевірки не зламані ──────────────────────────────────────────
async def test_self_as_host_rejected(db, redis):
    settings = get_settings()
    with pytest.raises(HTTPException) as e:
        await sync_group_from_host(
            str(uuid.uuid4()), _session(), db, redis,
            host_relay=settings.relay_name,
        )
    assert e.value.status_code == 400
    assert e.value.detail == "host_is_self_no_sync_needed"


async def test_malformed_group_id_rejected(db, redis):
    await _add_peer(db, TRUSTED_HOST, trusted=True)
    with pytest.raises(HTTPException) as e:
        await sync_group_from_host(
            "not-a-uuid", _session(), db, redis, host_relay=TRUSTED_HOST,
        )
    assert e.value.status_code == 400
    assert e.value.detail == "malformed_group_id"


async def test_rate_limit_enforced(db, redis, monkeypatch):
    await _add_peer(db, TRUSTED_HOST, trusted=True)

    async def fake_pull(*a, **kw):
        return None  # host_relay недоступний — не заважає перевірити ліміт
    monkeypatch.setattr(
        "morok_relay.federation_client.remote_pull_group_snapshot", fake_pull,
    )

    hit_429 = False
    for _ in range(15):
        try:
            await sync_group_from_host(
                str(uuid.uuid4()), _session(), db, redis, host_relay=TRUSTED_HOST,
            )
        except HTTPException as e:
            if e.status_code == 429:
                hit_429 = True
                break
    assert hit_429, "rate limit на /sync не спрацював"
