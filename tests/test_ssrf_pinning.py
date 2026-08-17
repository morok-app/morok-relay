"""
SSRF-guard федерації: pin-to-IP проти DNS rebinding (аудит зовн. №2, П.8).

Стара схема: getaddrinfo → перевірили IP → httpx конектиться ЗА
HOSTNAME (другий resolve). Attacker-controlled DNS відповідає двічі
по-різному: guard бачить публічну адресу, з'єднання йде у приватну
(127.0.0.1, 169.254.169.254...). Тепер TCP іде саме на перевірену
адресу; TLS SNI і верифікація — за hostname (доведено наживо проти
api.github.com: pin проходить, bare-IP без SNI падає з
CERTIFICATE_VERIFY_FAILED).
"""
from __future__ import annotations

import pytest

from morok_relay.federation_client import (
    is_safe_peer_hostname,
    resolve_pinned_peer,
)

pytestmark = pytest.mark.asyncio


async def test_private_targets_rejected(monkeypatch):
    """Хости, що резолвляться у приватне/локальне — відмова."""
    import socket

    cases = {
        "internal.example.com": [("127.0.0.1",)],
        "meta.example.com": [("169.254.169.254",)],
        "lan.example.com": [("10.0.0.5",)],
        "v6loc.example.com": [("::1",)],
    }

    def fake_gai(host, *a, **kw):
        if host in cases:
            return [(2, 1, 6, "", (ip[0], 443)) for ip in cases[host]]
        raise socket.gaierror

    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)
    for host in cases:
        assert await resolve_pinned_peer(host) is None, host


async def test_one_private_among_public_rejects_all(monkeypatch):
    """
    Rebinding-суміш: одна публічна + одна приватна адреса в одній
    відповіді → відмова повністю (не «беремо публічну»: пул адрес
    контролює той самий DNS).
    """
    import socket

    def fake_gai(host, *a, **kw):
        return [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("192.168.1.1", 443)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)
    assert await resolve_pinned_peer("mixed.example.com") is None


async def test_public_host_returns_pinned_ip(monkeypatch):
    import socket

    def fake_gai(host, *a, **kw):
        return [(2, 1, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)
    assert await resolve_pinned_peer("relay2.example.com") == "93.184.216.34"


async def test_garbage_hostnames_rejected():
    for bad in ("", "not a host", "http://x.com", "a" * 300,
                "127.0.0.1", "[::1]"):
        assert await resolve_pinned_peer(bad) is None
        assert is_safe_peer_hostname(bad) is False


async def test_nxdomain_fails_closed(monkeypatch):
    import socket

    def fake_gai(host, *a, **kw):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)
    assert await resolve_pinned_peer("nope.example.com") is None
