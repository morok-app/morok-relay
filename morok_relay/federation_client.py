"""
Federation client — outbound calls to other relays.

Used when this relay needs to forward an envelope to a recipient on another
relay, look up a username on a remote relay, or pull a group snapshot from
the group's host relay.

All outbound requests that mutate state are signed with our
MOROK_RELAY_PRIVKEY_HEX so the receiving relay can verify our identity.
"""
from __future__ import annotations

import logging
import time

import httpx

from . import crypto
from .config import get_settings

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS = 10.0

# ── SSRF guard ─────────────────────────────────────────────────────
# peer_hostname приходить із зовнішнього вводу (?relay=... у lookup,
# поля у federation-запитах). Без перевірки зловмисник змусить релей
# слати HTTPS на будь-який хост: внутрішні адреси (169.254.169.254
# метадані хмари, 127.0.0.1 локальні сервіси, 10.x/192.168.x інтранет)
# або довільні зовнішні хости (relay як проксі для сканування/DoS).
import ipaddress
import re
import socket

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def is_safe_peer_hostname(hostname: str) -> bool:
    """
    True лише якщо hostname — валідне публічне FQDN, що НЕ резолвиться
    у приватну/локальну адресу. Голі IP заборонені (федерація завжди
    по доменах). Будь-який сумнів = відмова (fail closed).
    """
    if not hostname or not _HOSTNAME_RE.match(hostname):
        return False
    # Заборонити голі IP, які пройшли б regex лише частково — і
    # перевірити, що домен не вказує на приватну мережу (DNS rebinding
    # пом'якшуємо: резолвимо й валідуємо всі A/AAAA записи).
    try:
        infos = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return False
    if not infos:
        return False
    for info in infos:
        ip_str = info[4][0]
        if not _is_public_ip(ip_str):
            return False
    return True



async def remote_handshake(peer_hostname: str) -> dict | None:
    settings = get_settings()
    timestamp = int(time.time())
    message = crypto.canonical_json({
        "morok_handshake": "v1",
        "hostname": settings.relay_name,
        "pubkey": settings.relay_pubkey_hex,
        "timestamp": timestamp,
    })
    try:
        privkey = bytes.fromhex(settings.relay_privkey_hex)
        signature = crypto.ed25519_sign(message, privkey)
    except (ValueError, TypeError):
        logger.error("Cannot sign handshake: relay privkey misconfigured")
        return None

    payload = {
        "peer_hostname": settings.relay_name,
        "peer_pubkey_hex": settings.relay_pubkey_hex,
        "timestamp": timestamp,
        "signature_hex": signature.hex(),
    }
    url = f"https://{peer_hostname}/api/v1/federation/handshake"
    if not is_safe_peer_hostname(peer_hostname):
        logger.warning("Blocked federation call to unsafe host: %r", peer_hostname)
        return None
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as e:
        logger.warning("Handshake to %s failed: %s", peer_hostname, e)
        return None


async def remote_forward(peer_hostname: str, envelope: dict) -> dict | None:
    """
    Forward a generic envelope (DM, group send, group delete, group
    snapshot push, ...) to another relay. The peer dispatches based on
    `envelope.kind` and `envelope.group_forward_mode`.
    """
    settings = get_settings()
    forwarded_at = int(time.time())

    message = crypto.canonical_json({
        "morok_forward": "v1",
        "envelope": envelope,
        "relay_pubkey": settings.relay_pubkey_hex,
        "forwarded_at": forwarded_at,
    })
    try:
        privkey = bytes.fromhex(settings.relay_privkey_hex)
        signature = crypto.ed25519_sign(message, privkey)
    except (ValueError, TypeError):
        logger.error("Cannot sign forward: relay privkey misconfigured")
        return None

    payload = {
        "envelope": envelope,
        "relay_pubkey_hex": settings.relay_pubkey_hex,
        "relay_signature_hex": signature.hex(),
        "forwarded_at": forwarded_at,
    }
    url = f"https://{peer_hostname}/api/v1/federation/forward"
    if not is_safe_peer_hostname(peer_hostname):
        logger.warning("Blocked federation call to unsafe host: %r", peer_hostname)
        return None
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as e:
        logger.warning("Forward to %s failed: %s", peer_hostname, e)
        return None


async def remote_lookup(peer_hostname: str, username: str) -> dict | None:
    """Look up a username on a remote relay. Public API, no signing needed."""
    url = f"https://{peer_hostname}/api/v1/federation/users/lookup/{username}"
    if not is_safe_peer_hostname(peer_hostname):
        logger.warning("Blocked federation call to unsafe host: %r", peer_hostname)
        return None
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(url)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as e:
        logger.warning("Lookup on %s failed: %s", peer_hostname, e)
        return None


async def remote_pull_group_snapshot(
    peer_hostname: str,
    group_id: str,
    caller_pubkey_hex: str,
) -> dict | None:
    """
    Pull current snapshot of a group from its host relay.

    Signed: peer host verifies our relay identity AND checks that
    caller_pubkey_hex is an actual member of the requested group before
    returning the snapshot (prevents arbitrary group enumeration).
    """
    settings = get_settings()
    timestamp = int(time.time())

    message = crypto.canonical_json({
        "morok_pull_snapshot": "v1",
        "group_id": group_id,
        "caller_pubkey": caller_pubkey_hex,
        "relay_pubkey": settings.relay_pubkey_hex,
        "timestamp": timestamp,
    })
    try:
        privkey = bytes.fromhex(settings.relay_privkey_hex)
        signature = crypto.ed25519_sign(message, privkey)
    except (ValueError, TypeError):
        logger.error("Cannot sign pull_snapshot: relay privkey misconfigured")
        return None

    payload = {
        "group_id": group_id,
        "caller_pubkey_hex": caller_pubkey_hex,
        "relay_pubkey_hex": settings.relay_pubkey_hex,
        "relay_signature_hex": signature.hex(),
        "timestamp": timestamp,
    }
    url = f"https://{peer_hostname}/api/v1/federation/group_snapshot/pull"
    if not is_safe_peer_hostname(peer_hostname):
        logger.warning("Blocked federation call to unsafe host: %r", peer_hostname)
        return None
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.post(url, json=payload)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as e:
        logger.warning("Pull snapshot from %s failed: %s", peer_hostname, e)
        return None
