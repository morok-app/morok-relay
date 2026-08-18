"""
Mail-out MX SSRF guard (аудит зовн. №3, MEDIUM).

Знахідка: send_external() резолвив MX через dns.resolver, а потім
smtplib.SMTP(host=mx, port=25, ...) сам ЗАНОВО резолвив hostname під
час connect() — без жодної перевірки, що результат публічний. Контро-
льований домен міг вказати MX на приватну/link-local адресу (10.x,
127.x, 169.254.169.254 — cloud metadata) і змусити mail-out вузол
зробити вихідне з'єднання у свою ж внутрішню мережу.

mail_out.py — окремий standalone-модуль (CX23, без FastAPI-стека),
тому тести працюють напряму з функціями, без conftest-фікстур relay.
"""
from __future__ import annotations

import socket

import pytest

from morok_relay.mail_out import _is_public_ip, _pinned_dns, _resolve_pinned_mx


# ── _is_public_ip ────────────────────────────────────────────────────────
def test_public_ipv4_accepted():
    assert _is_public_ip("93.184.216.34") is True


def test_private_ranges_rejected():
    for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.1",
               "127.0.0.1", "169.254.169.254", "0.0.0.0"):
        assert _is_public_ip(ip) is False, ip


def test_ipv6_loopback_and_link_local_rejected():
    assert _is_public_ip("::1") is False
    assert _is_public_ip("fe80::1") is False


def test_garbage_rejected():
    assert _is_public_ip("not-an-ip") is False
    assert _is_public_ip("") is False


# ── _resolve_pinned_mx ──────────────────────────────────────────────────
def test_resolve_pinned_mx_public(monkeypatch):
    def fake_gai(host, port, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)
    assert _resolve_pinned_mx("mx.example.com") == "93.184.216.34"


def test_resolve_pinned_mx_private_rejected(monkeypatch):
    """ГОЛОВНИЙ ТЕСТ. MX, що резолвиться у приватну адресу, — відмова."""
    def fake_gai(host, port, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)
    assert _resolve_pinned_mx("evil-mx.example.com") is None


def test_resolve_pinned_mx_metadata_ip_rejected(monkeypatch):
    """Cloud metadata endpoint — класична SSRF-ціль."""
    def fake_gai(host, port, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)
    assert _resolve_pinned_mx("metadata-mx.example.com") is None


def test_resolve_pinned_mx_mixed_addresses_rejected(monkeypatch):
    """Одна публічна + одна приватна в одній відповіді — відмова цілком
    (rebinding-суміш, той самий принцип, що для federation pin)."""
    def fake_gai(host, port, **kw):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", port)),
        ]
    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)
    assert _resolve_pinned_mx("mixed-mx.example.com") is None


def test_resolve_pinned_mx_dns_failure_fails_closed(monkeypatch):
    def fake_gai(host, port, **kw):
        raise socket.gaierror("NXDOMAIN")
    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)
    assert _resolve_pinned_mx("nonexistent.example.com") is None


# ── _pinned_dns: сам механізм підміни резолву ────────────────────────────
def test_pinned_dns_forces_specific_ip():
    calls = []
    real = socket.getaddrinfo

    with _pinned_dns("mx.example.com", "203.0.113.9"):
        result = socket.getaddrinfo("mx.example.com", 25)
        calls.append(result)

    assert calls[0][0][4][0] == "203.0.113.9", \
        "pinned DNS не повернув зафіксовану адресу"
    # після виходу з контексту — оригінальна функція відновлена
    assert socket.getaddrinfo is real


def test_pinned_dns_does_not_affect_other_hostnames(monkeypatch):
    """
    Підміна стосується ЛИШЕ заданого hostname — інші (яких тут бути не
    повинно, але про всяк випадок) ідуть через звичайний резолвер.
    """
    def fake_real_gai(host, port, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", port))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_real_gai)

    with _pinned_dns("pinned.example.com", "203.0.113.9"):
        pinned = socket.getaddrinfo("pinned.example.com", 25)
        other = socket.getaddrinfo("other.example.com", 25)

    assert pinned[0][4][0] == "203.0.113.9"
    assert other[0][4][0] == "1.2.3.4"


def test_pinned_dns_restores_on_exception():
    """Навіть якщо всередині блоку виняток — оригінальна функція
    повертається (finally), інакше наступний лист лишився б з
    підміненим DNS назавжди."""
    real = socket.getaddrinfo
    with pytest.raises(RuntimeError), _pinned_dns("mx.example.com", "203.0.113.9"):
        raise RuntimeError("simulated smtp failure")
    assert socket.getaddrinfo is real


# ── ipv6 pin ──────────────────────────────────────────────────────────────
def test_pinned_dns_ipv6_family():
    with _pinned_dns("mx6.example.com", "2001:db8::1"):
        result = socket.getaddrinfo("mx6.example.com", 25)
    assert result[0][0] == socket.AF_INET6
    assert result[0][4][0] == "2001:db8::1"
