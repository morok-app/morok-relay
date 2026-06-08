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
from ..push_sender import trigger_push

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


def _verify_delete_sig(
    *,
    kind: str,
    envelope_id: str,
    ts,
    sig_hex: str,
    signer_pubkey_hex: str,
    group_id: str | None = None,
    ts_window_seconds: int = 7 * 86400,
) -> bool:
    """
    Verify a sender's Ed25519 signature on a delete request that was
    forwarded through federation.

    The signed payload is the canonical_json of:
      DM:    {"kind":"dm_delete",     "envelope_id":..., "ts":...}
      Group: {"kind":"group_delete",  "group_id":..., "envelope_id":..., "ts":...}

    Returns True if the signature checks out AND ts is within the
    allowed window (defense against very-old replays). Returns False
    on any malformed input — caller is expected to reject the request.
    """
    # Type / range guards — these are fields from an untrusted envelope.
    try:
        ts_int = int(ts)
    except (TypeError, ValueError):
        return False
    import time as _t
    if abs(int(_t.time()) - ts_int) > ts_window_seconds:
        return False

    payload = {"kind": kind, "envelope_id": envelope_id, "ts": ts_int}
    if group_id is not None:
        payload["group_id"] = group_id
    message = crypto.canonical_json(payload)

    try:
        sig_bytes = bytes.fromhex(sig_hex)
        pubkey_bytes = bytes.fromhex(signer_pubkey_hex)
    except (TypeError, ValueError):
        return False
    if len(sig_bytes) != 64 or len(pubkey_bytes) != 32:
        return False

    try:
        return crypto.ed25519_verify(message, sig_bytes, pubkey_bytes)
    except Exception:  # noqa: BLE001 — verification failures must not 500
        return False


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
    try:
        return await _forward_impl(body, db, redis)
    except HTTPException as e:
        env_keys = list(body.envelope.keys()) if body.envelope else []
        logger.warning(
            "FORWARD_REJECTED status=%s detail=%s | envelope.kind=%s group_id=%s to=%s ts=%s keys=%s",
            e.status_code, e.detail,
            body.envelope.get("kind") if body.envelope else None,
            body.envelope.get("group_id") if body.envelope else None,
            body.envelope.get("to") if body.envelope else None,
            body.envelope.get("ts") if body.envelope else None,
            env_keys,
        )
        raise


async def _forward_impl(
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

    # 2. Check the relay is a known peer with matching pubkey AND trusted
    stmt = select(FederationPeer).where(FederationPeer.pubkey == relay_pubkey)
    peer = (await db.execute(stmt)).scalar_one_or_none()
    if peer is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="forwarding_relay_unknown_handshake_first",
        )
    if not peer.is_trusted:
        # Handshake succeeded but operator hasn't marked this peer as
        # trusted. We refuse to forward — open handshake is fine because
        # the local DB just records the candidate; trust is granted out
        # of band via SQL or admin panel.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="forwarding_relay_untrusted",
        )

    # ========================================================================
    # KIND-BASED DISPATCH (cross-relay group/DM control plane)
    # ========================================================================
    kind = body.envelope.get("kind")

    if kind == "group_snapshot":
        return await _handle_group_snapshot_push(body.envelope, peer, db)

    if kind == "dm_delete":
        return await _handle_dm_delete_forward(body.envelope, redis)

    if kind == "group_delete_to_host":
        return await _handle_group_delete_to_host(body.envelope, db, redis, settings)

    if kind == "group_delete_deliver":
        return await _handle_group_delete_deliver(body.envelope, db, redis, settings)

    if kind == "read_receipt":
        return await _handle_read_receipt(body.envelope, db, redis, settings)

    # ========================================================================
    # GROUP MESSAGE SEND HANDLING (existing — to_host / deliver)
    # ========================================================================
    group_id_str = body.envelope.get("group_id")
    if group_id_str:
        # Inner envelope is a real signed message — verify sender sig.
        # NOTE: we can't use crypto.verify_envelope_signature here because
        # for group envelopes `to` is a UUID (group_id), not a pubkey hex.
        # That function tries to bytes.fromhex(to) and fails on the dashes.
        try:
            inner_sender = bytes.fromhex(body.envelope["from"])
            inner_sig = bytes.fromhex(body.envelope["sig"])
        except (ValueError, KeyError, TypeError) as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"malformed_envelope_fields: {e}",
            )
        if len(inner_sender) != 32 or len(inner_sig) != 64:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="bad_inner_pubkey_or_sig_length",
            )
        # Timestamp sanity (same window as DM)
        try:
            inner_ts = int(body.envelope["ts"])
        except (KeyError, ValueError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="malformed_ts",
            )
        if inner_ts < now - 300 or inner_ts > now + 60:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="inner_envelope_timestamp_out_of_window",
            )
        unsigned = {
            k: body.envelope[k]
            for k in ("from", "to", "ts", "ttl", "blob")
            if k in body.envelope
        }
        canonical = crypto.canonical_json(unsigned)
        if not crypto.ed25519_verify(canonical, inner_sig, inner_sender):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="inner_envelope_invalid: signature_invalid",
            )
        return await _handle_group_forward(
            envelope=body.envelope,
            db=db,
            redis=redis,
            settings=settings,
        )

    # ========================================================================
    # DM HANDLING (existing path)
    # ========================================================================
    # DM also needs the inner signature verified.
    ok, err = crypto.verify_envelope_signature(body.envelope)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"inner_envelope_invalid: {err}",
        )

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
    # Best-effort push for the local recipient (sender side already pushed
    # any of its own local users; here we cover ours).
    try:
        await trigger_push(
            db=db, redis=redis,
            recipient_pubkeys_hex=[body.envelope["to"]],
            sender_username=body.envelope.get("from_username"),
        )
    except Exception as e:
        logger.warning("trigger_push (federation DM) failed: %s", e)

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
    # Push fanout to local offline members. The peer relay (sender side)
    # already pushed its own local members; we cover ours.
    try:
        await trigger_push(
            db=db, redis=redis,
            recipient_pubkeys_hex=known_local,
            sender_username=envelope.get("from_username"),
            group_id=str(gid),
        )
    except Exception as e:
        logger.warning("trigger_push (federation group deliver) failed: %s", e)
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


# ============================================================================
# CROSS-RELAY CONTROL-PLANE HANDLERS (group snapshot push/pull, deletes)
# ============================================================================

async def _handle_group_snapshot_push(
    envelope: dict,
    peer: "FederationPeer",
    db,
) -> "ForwardResponse":
    """
    Peer relay pushed us a snapshot of a group we should mirror locally
    (because we host members of it). Idempotent upsert.

    The peer's verified hostname is passed in so apply_group_snapshot
    can enforce "only the host may modify this group" — without it, a
    trusted-but-not-host peer could plant arbitrary admins/members.
    """
    from .groups import apply_group_snapshot

    try:
        await apply_group_snapshot(db, envelope, expected_home_relay=peer.hostname)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("apply_group_snapshot failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"snapshot_apply_failed: {type(e).__name__}",
        )
    return ForwardResponse(
        accepted=True,
        envelope_id=envelope.get("group_id", ""),
        reason="snapshot_applied",
    )


async def _handle_dm_delete_forward(envelope: dict, redis) -> "ForwardResponse":
    """
    Sender's home relay tells us a DM addressed to one of our local
    users should be deleted. Verify the sender's signature on the
    delete intent before acting — a trusted federation peer alone is
    not sufficient authorization, otherwise any peer could forge
    "alice deleted X" and censor our local users.
    """
    from ..queue import delete_envelope_by_sender

    envelope_id = envelope.get("envelope_id")
    recipient_pubkey_hex = envelope.get("recipient_pubkey_hex")
    caller_pubkey_hex = envelope.get("deleted_by_pubkey_hex")
    deleter_sig_hex = envelope.get("deleter_signature_hex")
    deleter_ts = envelope.get("deleter_ts")

    if not (envelope_id and recipient_pubkey_hex and caller_pubkey_hex):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="dm_delete_missing_fields",
        )
    if not deleter_sig_hex or deleter_ts is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="dm_delete_missing_signature",
        )

    if not _verify_delete_sig(
        kind="dm_delete",
        envelope_id=envelope_id,
        ts=deleter_ts,
        sig_hex=deleter_sig_hex,
        signer_pubkey_hex=caller_pubkey_hex,
    ):
        logger.warning(
            "Rejected federated dm_delete for %s — bad signature from claimed sender %s",
            envelope_id[:8] if envelope_id else "?",
            caller_pubkey_hex[:8] if caller_pubkey_hex else "?",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_delete_signature",
        )

    result = await delete_envelope_by_sender(
        redis=redis,
        envelope_id=envelope_id,
        caller_pubkey_hex=caller_pubkey_hex,
        recipient_pubkey_hex=recipient_pubkey_hex,
    )
    logger.info(
        "Federation dm_delete %s by %s... (queue_hit=%s, meta=%s, err=%s)",
        envelope_id[:8] if envelope_id else "?",
        caller_pubkey_hex[:8] if caller_pubkey_hex else "?",
        result.get("deleted_from_queue"),
        result.get("meta_existed"),
        result.get("error"),
    )
    return ForwardResponse(
        accepted=True,
        envelope_id=envelope_id,
        reason=result.get("error") or "dm_delete_done",
    )


async def _handle_read_receipt(
    envelope: dict, db, redis, settings,
) -> "ForwardResponse":
    """
    A peer relay tells us "your user X had a message read by Y".
    Verify the sender lives on our relay, then push a WS event.

    Read receipts are unsigned (cheap metadata). Acceptable risk: a
    misbehaving peer relay could fabricate receipts; the only effect
    is a misleading checkmark on the sender's screen.
    """
    from ..queue import publish_read_receipt as _publish_read

    envelope_id = envelope.get("envelope_id")
    sender_pubkey_hex = envelope.get("sender_pubkey_hex")
    reader_pubkey_hex = envelope.get("reader_pubkey_hex")
    group_id = envelope.get("group_id")

    if not (envelope_id and sender_pubkey_hex and reader_pubkey_hex):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="read_receipt_missing_fields",
        )

    # Sanity: the named sender must be local. Otherwise this receipt
    # doesn't belong on our relay.
    try:
        sender_pubkey = bytes.fromhex(sender_pubkey_hex)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="bad_sender_pubkey_hex",
        )

    stmt = (
        select(User)
        .where(User.pubkey == sender_pubkey)
        .where(User.deleted_at.is_(None))
    )
    sender_user = (await db.execute(stmt)).scalar_one_or_none()
    if sender_user is None or sender_user.home_relay != settings.relay_name:
        return ForwardResponse(
            accepted=False, envelope_id=envelope_id,
            reason="sender_not_on_this_relay",
        )

    await _publish_read(
        redis=redis,
        sender_pubkey_hex=sender_pubkey_hex,
        envelope_id=envelope_id,
        reader_pubkey_hex=reader_pubkey_hex,
        group_id=group_id,
    )
    logger.info(
        "Federation read_receipt for %s... (envelope %s..., reader %s...)",
        sender_pubkey_hex[:8], envelope_id[:8], reader_pubkey_hex[:8],
    )
    return ForwardResponse(
        accepted=True, envelope_id=envelope_id,
        reason="read_receipt_delivered",
    )


async def _handle_group_delete_to_host(
    envelope: dict, db, redis, settings,
) -> "ForwardResponse":
    """
    Peer relay forwarded us a group-delete request from one of their
    users. We're the host → authorize via meta (sender) OR admin →
    perform the full fan-out delete (local + federation to peers).

    The sender's signature on the delete intent is verified here AND
    re-propagated to other relays in the fan-out so they don't have
    to trust us as the host either.
    """
    from .groups import (
        _is_admin, _is_member, _load_group, _group_home_relay,
    )
    from ..queue import delete_envelope_for_group, get_envelope_meta

    envelope_id = envelope.get("envelope_id")
    group_id_str = envelope.get("group_id")
    caller_pubkey_hex = envelope.get("deleted_by_pubkey_hex")
    deleter_sig_hex = envelope.get("deleter_signature_hex")
    deleter_ts = envelope.get("deleter_ts")

    if not (envelope_id and group_id_str and caller_pubkey_hex):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="group_delete_to_host_missing_fields",
        )
    if not deleter_sig_hex or deleter_ts is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="group_delete_missing_signature",
        )
    try:
        gid = uuid.UUID(group_id_str)
        caller_bytes = bytes.fromhex(caller_pubkey_hex)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_id_or_pubkey",
        )

    if not _verify_delete_sig(
        kind="group_delete",
        envelope_id=envelope_id,
        ts=deleter_ts,
        sig_hex=deleter_sig_hex,
        signer_pubkey_hex=caller_pubkey_hex,
        group_id=str(gid),
    ):
        logger.warning(
            "Rejected federated group_delete %s — bad signature from claimed sender %s",
            envelope_id[:8], caller_pubkey_hex[:8],
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_delete_signature",
        )

    group = await _load_group(db, gid)

    home = _group_home_relay(group)
    if home != settings.relay_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="not_group_host",
        )

    if not _is_member(group, caller_bytes):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="caller_not_a_member",
        )

    meta = await get_envelope_meta(redis, envelope_id)
    sender_pubkey_hex = None
    if meta is not None:
        if meta.get("group_id") != str(group.id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="envelope_not_in_this_group",
            )
        sender_pubkey_hex = meta.get("from")
    is_sender = (
        sender_pubkey_hex is not None
        and sender_pubkey_hex == caller_pubkey_hex
    )
    is_admin = _is_admin(group, caller_bytes)
    if not (is_sender or is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="must_be_sender_or_admin",
        )

    # Same split-by-home-relay logic as delete_group_message host case.
    from ..models import FederationOutboundQueue, FedQueueStatus, User
    member_pubkeys_bytes = [m.pubkey for m in group.members]
    home_by_pubkey_hex: dict[str, str | None] = {}
    if member_pubkeys_bytes:
        stmt = (
            select(User.pubkey, User.home_relay)
            .where(User.pubkey.in_(member_pubkeys_bytes))
            .where(User.deleted_at.is_(None))
        )
        rows = (await db.execute(stmt)).all()
        for pk, hr in rows:
            home_by_pubkey_hex[bytes(pk).hex()] = hr

    local_recipients: list[str] = []
    remote_by_relay: dict[str, list[str]] = {}
    for m in group.members:
        pk_hex = m.pubkey.hex()
        h = home_by_pubkey_hex.get(pk_hex)
        if h is None or h == settings.relay_name:
            local_recipients.append(pk_hex)
        else:
            remote_by_relay.setdefault(h, []).append(pk_hex)

    await delete_envelope_for_group(
        redis=redis,
        envelope_id=envelope_id,
        group_id=str(group.id),
        recipient_pubkeys_hex=local_recipients,
        deleted_by_pubkey_hex=caller_pubkey_hex,
    )

    import time as _t
    now = int(_t.time())
    for target_relay, members_on_relay in remote_by_relay.items():
        deliver_payload = {
            "kind": "group_delete_deliver",
            "group_id": str(group.id),
            "envelope_id": envelope_id,
            "deleted_by_pubkey_hex": caller_pubkey_hex,
            "deliver_to_pubkeys": members_on_relay,
            # Re-propagate the verified sender signature unchanged so
            # the delivering relay can verify it locally rather than
            # trust us (the host) as a federation hop.
            "deleter_signature_hex": deleter_sig_hex,
            "deleter_ts": deleter_ts,
        }
        from .groups import _synthetic_queue_id
        synthetic_id = _synthetic_queue_id("deldlv", envelope_id, target_relay)
        dup_stmt = (
            select(FederationOutboundQueue)
            .where(FederationOutboundQueue.envelope_id == synthetic_id)
            .where(FederationOutboundQueue.target_relay == target_relay)
            .limit(1)
        )
        existing = (await db.execute(dup_stmt)).scalar_one_or_none()
        if existing is None:
            db.add(FederationOutboundQueue(
                envelope_id=synthetic_id,
                envelope_data=deliver_payload,
                target_relay=target_relay,
                status=FedQueueStatus.PENDING,
                attempts=0,
                next_attempt_at=now,
                created_at=now,
            ))
    if remote_by_relay:
        await db.flush()

    logger.info(
        "Federation group_delete_to_host %s by %s... applied (local=%d, remote_relays=%d)",
        envelope_id[:8], caller_pubkey_hex[:8],
        len(local_recipients), len(remote_by_relay),
    )
    return ForwardResponse(accepted=True, envelope_id=envelope_id)


async def _handle_group_delete_deliver(
    envelope: dict, db, redis, settings,
) -> "ForwardResponse":
    """
    Host relay tells us: drop this group envelope from these specific
    local member inboxes and push a "deleted" WS event to each.

    The host has already verified the sender's authorization. We
    independently re-verify the sender's signature on the delete
    intent — this means a compromised host cannot censor messages
    in our local users' inboxes by forging deletes.
    """
    from ..queue import delete_envelope_for_group
    from ..models import User

    envelope_id = envelope.get("envelope_id")
    group_id_str = envelope.get("group_id")
    caller_pubkey_hex = envelope.get("deleted_by_pubkey_hex")
    raw_recipients = envelope.get("deliver_to_pubkeys") or []
    deleter_sig_hex = envelope.get("deleter_signature_hex")
    deleter_ts = envelope.get("deleter_ts")

    if not (envelope_id and group_id_str and caller_pubkey_hex and raw_recipients):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="group_delete_deliver_missing_fields",
        )
    if not deleter_sig_hex or deleter_ts is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="group_delete_missing_signature",
        )

    if not _verify_delete_sig(
        kind="group_delete",
        envelope_id=envelope_id,
        ts=deleter_ts,
        sig_hex=deleter_sig_hex,
        signer_pubkey_hex=caller_pubkey_hex,
        group_id=group_id_str,
    ):
        logger.warning(
            "Rejected federated group_delete_deliver %s — bad signature from claimed sender %s",
            envelope_id[:8], caller_pubkey_hex[:8],
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_delete_signature",
        )

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

    # Filter to actually-local users (defensive)
    stmt = (
        select(User.pubkey, User.home_relay)
        .where(User.pubkey.in_(recipient_bytes))
        .where(User.deleted_at.is_(None))
    )
    rows = (await db.execute(stmt)).all()
    known_local = [
        bytes(pk).hex() for pk, hr in rows
        if hr == settings.relay_name
    ]
    if not known_local:
        # All requested pubkeys are unknown or non-local — nothing to do.
        return ForwardResponse(
            accepted=True, envelope_id=envelope_id,
            reason="no_local_recipients",
        )

    result = await delete_envelope_for_group(
        redis=redis,
        envelope_id=envelope_id,
        group_id=group_id_str,
        recipient_pubkeys_hex=known_local,
        deleted_by_pubkey_hex=caller_pubkey_hex,
    )
    logger.info(
        "Federation group_delete_deliver %s for %d local recipients (hits=%d)",
        envelope_id[:8], len(known_local), result["deleted_from_count"],
    )
    return ForwardResponse(accepted=True, envelope_id=envelope_id)


# ============================================================================
# PULL SNAPSHOT (peer requests current group state from host)
# ============================================================================

class PullSnapshotRequest(BaseModel):
    group_id: str = Field(..., min_length=36, max_length=36)
    caller_pubkey_hex: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    relay_pubkey_hex: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    relay_signature_hex: str = Field(..., pattern=r"^[0-9a-f]{128}$")
    timestamp: int = Field(..., ge=0)


@router.post(
    "/group_snapshot/pull",
    summary="Peer pulls a group snapshot from us (we're the host)",
)
async def pull_group_snapshot(
    body: PullSnapshotRequest,
    db: DBSession,
) -> dict:
    """
    Peer relay calls this to fetch a group's current state. Required
    because peer-side users may receive a group_key DM before any push
    snapshot landed (e.g., legacy data, or invite-token join flow).

    Auth:
      1. Peer relay signs (group_id, caller_pubkey, our_pubkey, ts).
      2. We verify the signature against a known peer in federation_peers.
      3. The caller_pubkey MUST be a member of the requested group, or
         we 404 — prevents peer-relay enumeration of groups.
    """
    from .groups import _serialize_group_for_snapshot, _is_member
    settings = get_settings()
    now = int(time.time())

    if abs(now - body.timestamp) > 300:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="timestamp_out_of_window",
        )

    try:
        relay_pubkey = bytes.fromhex(body.relay_pubkey_hex)
        relay_sig = bytes.fromhex(body.relay_signature_hex)
        gid = uuid.UUID(body.group_id)
        caller_bytes = bytes.fromhex(body.caller_pubkey_hex)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed_hex_or_uuid",
        )

    message = crypto.canonical_json({
        "morok_pull_snapshot": "v1",
        "group_id": body.group_id,
        "caller_pubkey": body.caller_pubkey_hex,
        "relay_pubkey": body.relay_pubkey_hex,
        "timestamp": body.timestamp,
    })
    if not crypto.ed25519_verify(message, relay_sig, relay_pubkey):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="relay_signature_invalid",
        )

    peer_stmt = select(FederationPeer).where(FederationPeer.pubkey == relay_pubkey)
    peer = (await db.execute(peer_stmt)).scalar_one_or_none()
    if peer is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="relay_unknown_handshake_first",
        )
    if not peer.is_trusted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="relay_untrusted",
        )

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

    home = group.home_relay or settings.relay_name
    if home != settings.relay_name:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="group_not_hosted_here",
        )

    if not _is_member(group, caller_bytes):
        # Don't reveal that group exists — 404 like above.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="group_not_found",
        )

    return _serialize_group_for_snapshot(group)
