"""
Federation API — relay ↔ relay communication.

This is how messages addressed to users on OTHER relays get delivered.
When User A on relay1 wants to message User B on relay2, the flow is:

  client_A → relay1: POST /api/v1/messages  (envelope to user_B)
  relay1   → relay2: POST /api/v1/federation/forward  (signed forward)
  relay2 enqueues for user_B; user_B receives via their inbox WS

For GROUP messages the envelope carries `group_id` and a routing hint
`group_forward_mode`:

  "to_host"  — sender's home relay forwards the original envelope to the
               group's host relay; host then does the real fan-out.
  "deliver"  — host relay tells a peer relay to enqueue the same
               envelope for a specific list of local members
               (`deliver_to_pubkeys`).

Authentication
--------------
Federation requests are signed by the originating relay using its
MOROK_RELAY_PRIVKEY_HEX. Receiving relay looks up the sender relay's
public key in its federation_peers table and verifies the signature.

For v0.3 we keep federation minimal:
- /handshake — exchange pubkeys + greeting; verifies peer identity
- /forward   — accept an envelope from another relay (DM or group)
- /lookup    — public username lookup (no signing required)
"""
from __future__ import annotations

import base64
import logging
import time
import uuid

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from .. import blob_storage, crypto
from ..config import get_settings
from ..deps import DBSession, RedisClient
from ..models import FederationPeer, Group, GroupMember, User
from ..queue import enqueue_envelope, enqueue_envelope_for_recipients, envelope_exists

logger = logging.getLogger(__name__)

router = APIRouter(tags=["federation"])


# ============================================================================
# SCHEMAS (federation-internal — not in public schemas.py)
# ============================================================================

class HandshakeRequest(BaseModel):
    """Peer relay introduces itself."""
    peer_hostname: str = Field(..., max_length=255)
    peer_pubkey_hex: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    timestamp: int = Field(..., ge=0)
    signature_hex: str = Field(..., pattern=r"^[0-9a-f]{128}$")


class HandshakeResponse(BaseModel):
    accepted: bool
    our_pubkey_hex: str
    our_relay_name: str


class ForwardRequest(BaseModel):
    """One relay forwards an envelope to another."""
    envelope: dict     # the original signed envelope from the sender
    relay_pubkey_hex: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    relay_signature_hex: str = Field(..., pattern=r"^[0-9a-f]{128}$")
    forwarded_at: int = Field(..., ge=0)


class ForwardResponse(BaseModel):
    accepted: bool
    envelope_id: str
    reason: str | None = None


# ============================================================================
# HELPERS
# ============================================================================

def _handshake_message(peer_hostname: str, peer_pubkey_hex: str, timestamp: int) -> bytes:
    """Canonical bytes that a peer signs for handshake."""
    return crypto.canonical_json({
        "morok_handshake": "v1",
        "hostname": peer_hostname,
        "pubkey": peer_pubkey_hex,
        "timestamp": timestamp,
    })


def _forward_message(envelope: dict, relay_pubkey_hex: str, forwarded_at: int) -> bytes:
    """Canonical bytes that a relay signs when forwarding an envelope."""
    return crypto.canonical_json({
        "morok_forward": "v1",
        "envelope": envelope,
        "relay_pubkey": relay_pubkey_hex,
        "forwarded_at": forwarded_at,
    })


async def _get_or_create_peer(
    db,
    hostname: str,
    pubkey_bytes: bytes,
) -> FederationPeer:
    """
    Idempotently record a federation peer. Trust starts False; operator
    promotes manually (or via TOFU policy — out of scope for v0.3).
    """
    stmt = select(FederationPeer).where(FederationPeer.hostname == hostname)
    peer = (await db.execute(stmt)).scalar_one_or_none()
    if peer is not None:
        # If the pubkey changed, that's a Trust-On-First-Use violation.
        # For v0.3 we LOG it and reject — operator must manually re-trust.
        if peer.pubkey != pubkey_bytes:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="peer_pubkey_changed_manual_intervention_required",
            )
        peer.last_handshake_at = int(time.time())
        return peer

    peer = FederationPeer(
        hostname=hostname,
        pubkey=pubkey_bytes,
        is_trusted=False,
        last_handshake_at=int(time.time()),
    )
    db.add(peer)
    await db.flush()
    return peer


# ============================================================================
# ENDPOINTS
# ============================================================================

@router.post(
    "/handshake",
    response_model=HandshakeResponse,
    summary="Federation handshake — peer relay introduces itself",
)
async def handshake(
    body: HandshakeRequest,
    db: DBSession,
) -> HandshakeResponse:
    """
    Receive a federation handshake from another relay.

    Verifies the peer's signature over (hostname, pubkey, timestamp). On
    success, records the peer in our federation_peers table (untrusted by
    default). Returns our own relay identity so the peer can record us.
    """
    settings = get_settings()
    now = int(time.time())

    # 1. Time bound check (prevent replay)
    if abs(now - body.timestamp) > 300:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="handshake_timestamp_out_of_window",
        )

    # 2. Verify signature
    try:
        peer_pubkey = bytes.fromhex(body.peer_pubkey_hex)
        signature = bytes.fromhex(body.signature_hex)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_hex",
        )

    message = _handshake_message(
        body.peer_hostname, body.peer_pubkey_hex, body.timestamp
    )
    if not crypto.ed25519_verify(message, signature, peer_pubkey):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="handshake_signature_invalid",
        )

    # 3. Record peer (TOFU — first time we see this hostname, save the key)
    await _get_or_create_peer(db, body.peer_hostname, peer_pubkey)

    return HandshakeResponse(
        accepted=True,
        our_pubkey_hex=settings.relay_pubkey_hex,
        our_relay_name=settings.relay_name,
    )


@router.post(
    "/forward",
    response_model=ForwardResponse,
    summary="Accept an envelope forwarded from another relay",
)
async def forward(
    body: ForwardRequest,
    db: DBSession,
    redis: RedisClient,
) -> ForwardResponse:
    """
    Another relay is forwarding an envelope to one of our local users.

    Two layers of verification:
    1. The forwarding relay must be a known peer (verified by their pubkey).
    2. The original envelope must have a valid sender signature.

    We don't decrypt — just verify, store blob, enqueue for the recipient.
    """
    settings = get_settings()
    now = int(time.time())

    # 1. Verify the forwarding relay's signature over the forward request
    try:
        relay_pubkey = bytes.fromhex(body.relay_pubkey_hex)
        relay_sig = bytes.fromhex(body.relay_signature_hex)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_hex",
        )

    if abs(now - body.forwarded_at) > 300:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="forward_timestamp_out_of_window",
        )

    msg = _forward_message(body.envelope, body.relay_pubkey_hex, body.forwarded_at)
    if not crypto.ed25519_verify(msg, relay_sig, relay_pubkey):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="forwarding_relay_signature_invalid",
        )

    # 2. Check the relay is a known peer with matching pubkey
    stmt = select(FederationPeer).where(FederationPeer.pubkey == relay_pubkey)
    peer = (await db.execute(stmt)).scalar_one_or_none()
    if peer is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="forwarding_relay_unknown_handshake_first",
        )

    # 3. Verify the inner envelope (original sender's signature)
    ok, err = crypto.verify_envelope_signature(body.envelope)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"inner_envelope_invalid: {err}",
        )

    # ========================================================================
    # GROUP MESSAGE HANDLING
    # ========================================================================
    group_id_str = body.envelope.get("group_id")
    if group_id_str:
        return await _handle_group_forward(
            envelope=body.envelope,
            db=db,
            redis=redis,
            settings=settings,
        )

    # ========================================================================
    # DM HANDLING (existing path)
    # ========================================================================
    # 4. Recipient must be on this relay — look up by pubkey
    try:
        recipient_pubkey = bytes.fromhex(body.envelope["to"])
    except (ValueError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_recipient_in_envelope",
        )

    stmt = select(User).where(User.pubkey == recipient_pubkey)
    recipient = (await db.execute(stmt)).scalar_one_or_none()
    if recipient is None or recipient.home_relay != settings.relay_name:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="recipient_not_on_this_relay",
        )

    # 5. Decode blob, check size
    try:
        blob_bytes = base64.b64decode(body.envelope["blob"], validate=True)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="blob_not_base64",
        )
    if len(blob_bytes) > settings.max_blob_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="blob_too_large",
        )

    # 6. Compute envelope ID and dedup
    envelope = crypto.MessageEnvelope(
        sender_pubkey=bytes.fromhex(body.envelope["from"]),
        recipient_pubkey=recipient_pubkey,
        timestamp=int(body.envelope["ts"]),
        ttl_seconds=int(body.envelope["ttl"]),
        blob=blob_bytes,
    )
    envelope_id = envelope.envelope_id

    if await envelope_exists(redis, envelope_id):
        return ForwardResponse(
            accepted=True,
            envelope_id=envelope_id,
            reason="duplicate_already_queued",
        )

    # 7. Persist
    await blob_storage.write_blob(envelope_id, blob_bytes)
    await enqueue_envelope(
        redis=redis,
        envelope_id=envelope_id,
        sender_pubkey_hex=body.envelope["from"],
        recipient_pubkey_hex=body.envelope["to"],
        timestamp=int(body.envelope["ts"]),
        ttl_seconds=int(body.envelope["ttl"]),
        signature_hex=body.envelope["sig"],
        hard_ceiling_seconds=settings.message_ttl_hard_seconds,
    )

    return ForwardResponse(accepted=True, envelope_id=envelope_id)


async def _handle_group_forward(
    envelope: dict,
    db,
    redis,
    settings,
) -> "ForwardResponse":
    """
    Group message arrived via federation. Two sub-modes:

      to_host:  sender's relay shipping the original signed envelope to
                us because we host this group. We do the real fan-out.

      deliver:  group host telling us to enqueue this envelope for a
                specific subset of members that live on this relay.

    Any other / missing mode → 400.
    """
    # Late import to avoid circular: groups.py imports from queue,
    # and we already import enqueue helpers from queue here.
    from .groups import compute_group_envelope_id, do_group_fanout, _is_member

    mode = envelope.get("group_forward_mode")
    group_id_str = envelope.get("group_id")

    if mode not in ("to_host", "deliver"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unknown_or_missing_group_forward_mode",
        )

    try:
        gid = uuid.UUID(group_id_str)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_group_id",
        )

    try:
        sender_pubkey = bytes.fromhex(envelope["from"])
    except (ValueError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_envelope_from",
        )

    try:
        ts = int(envelope["ts"])
        ttl = int(envelope["ttl"])
        blob_b64 = envelope["blob"]
        sig_hex = envelope["sig"]
    except (KeyError, TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_envelope_fields",
        )

    try:
        blob_bytes = base64.b64decode(blob_b64, validate=True)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="blob_not_base64",
        )
    if len(blob_bytes) > settings.max_blob_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="blob_too_large",
        )

    envelope_id = compute_group_envelope_id(
        sender_pubkey, gid.bytes, ts, blob_bytes,
    )

    # Cross-hop dedup: if we've already seen this envelope, ack and bail.
    if await envelope_exists(redis, envelope_id):
        return ForwardResponse(
            accepted=True, envelope_id=envelope_id,
            reason="duplicate_already_processed",
        )

    if mode == "to_host":
        # Load the group; we must be its host.
        stmt = (
            select(Group)
            .options(selectinload(Group.members))
            .where(Group.id == gid)
            .where(Group.deleted_at.is_(None))
        )
        group = (await db.execute(stmt)).scalar_one_or_none()
        if group is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="group_not_found",
            )

        group_home = group.home_relay or settings.relay_name
        if group_home != settings.relay_name:
            # Forwarder picked the wrong relay; we won't relay further to
            # avoid loops. They should consult /federation/users/lookup
            # or maintain group_home metadata.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="not_group_host",
            )

        if not _is_member(group, sender_pubkey):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="sender_not_a_member",
            )

        await blob_storage.write_blob(envelope_id, blob_bytes)

        # Use whatever sender_username the forwarder supplied; we don't
        # re-resolve from our DB because the user may not exist locally.
        envelope_for_fanout = {
            "from": envelope["from"],
            "to": str(gid),
            "ts": ts,
            "ttl": ttl,
            "blob": blob_b64,
            "sig": sig_hex,
            "from_username": envelope.get("from_username"),
        }
        local_count, remote_relay_count = await do_group_fanout(
            group=group,
            envelope=envelope_for_fanout,
            envelope_id=envelope_id,
            db=db,
            redis=redis,
        )
        logger.info(
            "Group forward to_host %s: local=%d remote_relays=%d",
            envelope_id[:8], local_count, remote_relay_count,
        )
        return ForwardResponse(accepted=True, envelope_id=envelope_id)

    # mode == "deliver"
    raw_recipients = envelope.get("deliver_to_pubkeys") or []
    if not isinstance(raw_recipients, list) or not raw_recipients:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_deliver_to_pubkeys",
        )

    # Sanity: every recipient must be a real local user.
    recipient_bytes: list[bytes] = []
    for pk in raw_recipients:
        if not isinstance(pk, str) or len(pk) != 64:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="malformed_deliver_pubkey",
            )
        try:
            recipient_bytes.append(bytes.fromhex(pk))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="malformed_deliver_pubkey",
            )

    stmt = (
        select(User.pubkey, User.home_relay)
        .where(User.pubkey.in_(recipient_bytes))
        .where(User.deleted_at.is_(None))
    )
    rows = (await db.execute(stmt)).all()
    known_local: list[str] = []
    for pk, hr in rows:
        if hr == settings.relay_name:
            known_local.append(bytes(pk).hex())

    if not known_local:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="no_local_recipients_in_deliver_list",
        )

    await blob_storage.write_blob(envelope_id, blob_bytes)
    await enqueue_envelope_for_recipients(
        redis=redis,
        envelope_id=envelope_id,
        sender_pubkey_hex=envelope["from"],
        recipient_pubkeys_hex=known_local,
        timestamp=ts,
        ttl_seconds=ttl,
        signature_hex=sig_hex,
        hard_ceiling_seconds=settings.message_ttl_hard_seconds,
        group_id=str(gid),
        sender_username=envelope.get("from_username"),
    )
    logger.info(
        "Group forward deliver %s: enqueued for %d local recipients",
        envelope_id[:8], len(known_local),
    )
    return ForwardResponse(accepted=True, envelope_id=envelope_id)


@router.get(
    "/users/lookup/{username}",
    summary="Public username lookup for federation",
)
async def federation_lookup(
    username: str,
    db: DBSession,
) -> dict:
    """
    Public username lookup — other relays use this to find which relay
    hosts a given @username before forwarding.

    Same behavior as /api/v1/users/lookup but explicitly part of the
    federation API.
    """
    from ..schemas import normalize_username

    normalized = normalize_username(username)
    stmt = select(User).where(User.username == normalized).where(
        User.deleted_at.is_(None)
    )
    user = (await db.execute(stmt)).scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="username_not_found",
        )

    return {
        "pubkey_hex": user.pubkey.hex(),
        "username": user.username,
        "home_relay": user.home_relay,
    }
