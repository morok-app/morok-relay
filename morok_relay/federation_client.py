"""
Federation client — outbound calls to other relays.

Used when this relay needs to forward an envelope to a recipient on another
relay, or look up a username known to be on a remote relay.

All outbound requests are signed with our MOROK_RELAY_PRIVKEY_HEX so the
receiving relay can verify our identity.
"""
from __future__ import annotations

import logging
import time

import httpx

from . import crypto
from .config import get_settings

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS = 10.0


async def remote_handshake(peer_hostname: str) -> dict | None:
    """
    Perform a handshake with a remote relay.

    Returns the peer's response on success, None on failure.
    """
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
    Forward an envelope to another relay for delivery to one of its users.

    Returns the remote response on success, None on failure.
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
