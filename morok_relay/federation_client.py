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

import asyncio
import enum

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


async def resolve_pinned_peer(hostname: str) -> str | None:
    """
    Резолвить hostname, валідує ВСІ адреси як публічні й повертає ОДНУ
    перевірену адресу для pin-to-IP підключення.

    ЧОМУ (аудит зовн. №2, П.8 — DNS rebinding TOCTOU). Стара схема:
    getaddrinfo → перевірили IP → httpx конектиться ЗА HOSTNAME, тобто
    робить ДРУГИЙ resolve. Attacker-controlled DNS міг відповісти двічі
    по-різному: перша відповідь публічна (guard пропустив), друга —
    127.0.0.1/169.254.169.254 (запит пішов у внутрішню мережу). Тепер
    з'єднання йде саме на ту адресу, яку перевірили; другого resolve
    не існує.

    Заодно: getaddrinfo синхронний і раніше викликався прямо в async-
    потоці — повільний DNS блокував увесь event loop. Тепер у to_thread.

    Fail closed: будь-яка помилка/приватна адреса → None.
    """
    if not hostname or not _HOSTNAME_RE.match(hostname):
        return None
    try:
        infos = await asyncio.to_thread(
            socket.getaddrinfo, hostname, 443, proto=socket.IPPROTO_TCP,
        )
    except (socket.gaierror, UnicodeError, OSError):
        return None
    if not infos:
        return None
    ips = []
    for info in infos:
        ip_str = info[4][0]
        if not _is_public_ip(ip_str):
            return None          # хоч одна приватна — відмова повністю
        ips.append(ip_str)
    return ips[0]


async def _pinned_post(
    hostname: str, path: str, payload: dict,
) -> httpx.Response | None:
    """
    POST на peer із pin-to-IP: TCP — на перевірену адресу, TLS SNI і
    верифікація сертифіката — за hostname (httpx-розширення
    sni_hostname), Host-заголовок — hostname. Повертає Response або
    None, якщо host небезпечний.
    """
    ip = await resolve_pinned_peer(hostname)
    if ip is None:
        logger.warning("Blocked federation call to unsafe host: %r", hostname)
        return None
    # IPv6 у URL — в квадратних дужках
    host_for_url = f"[{ip}]" if ":" in ip else ip
    url = f"https://{host_for_url}{path}"
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        return await client.post(
            url, json=payload,
            headers={"Host": hostname},
            extensions={"sni_hostname": hostname},
        )


async def _pinned_get(hostname: str, path: str) -> httpx.Response | None:
    ip = await resolve_pinned_peer(hostname)
    if ip is None:
        logger.warning("Blocked federation call to unsafe host: %r", hostname)
        return None
    host_for_url = f"[{ip}]" if ":" in ip else ip
    url = f"https://{host_for_url}{path}"
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        return await client.get(
            url,
            headers={"Host": hostname},
            extensions={"sni_hostname": hostname},
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
    try:
        response = await _pinned_post(
            peer_hostname, "/api/v1/federation/handshake", payload,
        )
        if response is None:
            return None
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
    try:
        response = await _pinned_post(
            peer_hostname, "/api/v1/federation/forward", payload,
        )
        if response is None:
            return None
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as e:
        logger.warning("Forward to %s failed: %s", peer_hostname, e)
        return None


class LookupOutcome(str, enum.Enum):
    """
    Типізований результат remote_lookup (аудит зовн. №3, MEDIUM).

    Раніше і "peer каже 404 — юзера нема" і "peer недоступний/помилка"
    поверталися однаковим None — верхній рівень (_remote_lookup_with_
    retry) не міг їх розрізнити і трактував БУДЬ-ЯКИЙ None як
    підтверджену відсутність користувача, ставлячи негативний кеш на
    основі мережевого збою. Власний коментар коду це визнавав: "we
    can't tell from here". Тимчасово мертвий peer виглядав як "такого
    юзернейма не існує".
    """
    FOUND = "found"
    NOT_FOUND = "not_found"        # peer відповів: юзера немає (справжній 404)
    TRANSIENT_ERROR = "transient"  # мережа/timeout/5xx — стан невідомий


async def remote_lookup(
    peer_hostname: str, username: str,
) -> tuple["LookupOutcome", dict | None]:
    """Look up a username on a remote relay. Public API, no signing needed."""
    try:
        response = await _pinned_get(
            peer_hostname, f"/api/v1/federation/users/lookup/{username}",
        )
        if response is None:
            return LookupOutcome.TRANSIENT_ERROR, None
        if response.status_code == 404:
            return LookupOutcome.NOT_FOUND, None
        response.raise_for_status()
        return LookupOutcome.FOUND, response.json()
    except httpx.HTTPError as e:
        logger.warning("Lookup on %s failed: %s", peer_hostname, e)
        return LookupOutcome.TRANSIENT_ERROR, None


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
    try:
        response = await _pinned_post(
            peer_hostname, "/api/v1/federation/group_snapshot/pull", payload,
        )
        if response is None:
            return None
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as e:
        logger.warning("Pull snapshot from %s failed: %s", peer_hostname, e)
        return None
