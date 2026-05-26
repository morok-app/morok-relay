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
