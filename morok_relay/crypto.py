"""
Cryptographic primitives for Morok relay.

Design principles
-----------------
1. Server NEVER has access to user private keys. All client-side crypto
   (Ed25519 sign, X25519 ECDH, message encryption) is here only for
   *verification* purposes — verifying signatures from clients.

2. No fallbacks that silently weaken security. If a primitive is unavailable,
   we crash on import. Better than silently accepting unsigned messages.
   This is the lesson from lac_crypto.py:124 (`return True` fallback) and
   lac_crypto.py:148 (unsigned tx accepted).

3. No hand-rolled crypto. Ring signatures, stealth addresses etc. that
   were in lac_crypto.py are NOT here — they were broken there, and we
   don't need them for a messenger anyway.

4. Canonical serialization is strict and explicit, not "just JSON sort_keys".

Library: PyNaCl (libsodium bindings) — battle-tested, audited.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any

import nacl.bindings
import nacl.exceptions
import nacl.public
import nacl.signing
import nacl.utils


# ============================================================================
# CANONICAL SERIALIZATION
# ============================================================================

def canonical_json(obj: Any) -> bytes:
    """
    Deterministic JSON serialization for signing.

    Produces identical bytes for equivalent objects regardless of Python
    dict order, whitespace, or float representation. Required because
    signing operates on bytes — different serialization = different signature.

    Rules:
    - sorted keys
    - no whitespace
    - no NaN/Infinity (raise instead)
    - integers stay integers (no 1.0 vs 1 ambiguity)
    - UTF-8 output
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


# ============================================================================
# Ed25519 SIGNATURES (identity & message auth)
# ============================================================================

@dataclass(frozen=True, slots=True)
class Ed25519Keypair:
    """An Ed25519 signing keypair. Private key never leaves the client
    in production — this dataclass is used server-side only for the relay's
    own keypair (federation auth) and in tests."""
    public_key: bytes  # 32 bytes
    private_key: bytes  # 32 bytes (seed; signing key is derived)

    @property
    def public_key_hex(self) -> str:
        return self.public_key.hex()

    @property
    def private_key_hex(self) -> str:
        return self.private_key.hex()

    @classmethod
    def generate(cls) -> "Ed25519Keypair":
        sk = nacl.signing.SigningKey.generate()
        return cls(
            public_key=bytes(sk.verify_key),
            private_key=bytes(sk),
        )

    @classmethod
    def from_seed(cls, seed: bytes) -> "Ed25519Keypair":
        if len(seed) != 32:
            raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")
        sk = nacl.signing.SigningKey(seed)
        return cls(
            public_key=bytes(sk.verify_key),
            private_key=bytes(sk),
        )


def ed25519_sign(message: bytes, private_key: bytes) -> bytes:
    """
    Sign a message with Ed25519. Returns 64-byte signature.

    Used server-side ONLY for the relay's own messages
    (federation API requests). Never for user messages.
    """
    if len(private_key) != 32:
        raise ValueError(f"Ed25519 private key must be 32 bytes, got {len(private_key)}")
    sk = nacl.signing.SigningKey(private_key)
    return sk.sign(message).signature


def ed25519_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify Ed25519 signature.

    Returns True only on a valid signature. NEVER returns True for missing
    signature or missing pubkey — that was the bug in lac_crypto.py:148.

    All exceptions are caught and converted to False so callers don't have
    to handle them, but a malformed signature/key returns False, not raises.
    """
    if not signature or not public_key:
        return False
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        vk = nacl.signing.VerifyKey(public_key)
        vk.verify(message, signature)
        return True
    except (nacl.exceptions.BadSignatureError, ValueError, TypeError):
        return False


# ============================================================================
# X25519 KEY EXCHANGE (for sealed messages)
# ============================================================================
# These functions exist so the relay can verify that a client knows the
# right keypair. Actual message encryption/decryption happens client-side.

def x25519_pubkey_from_ed25519(ed_pubkey: bytes) -> bytes:
    """
    Convert Ed25519 public key to X25519 (Curve25519) public key.

    Same underlying curve, different encoding. This lets us use one
    identity keypair for both signing and key exchange without storing
    two keys per user.
    """
    if len(ed_pubkey) != 32:
        raise ValueError(f"Ed25519 pubkey must be 32 bytes, got {len(ed_pubkey)}")
    return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(ed_pubkey)


# ============================================================================
# CHALLENGE-RESPONSE AUTHENTICATION
# ============================================================================
# Used by clients to prove they own a pubkey without sending the privkey.
# Flow:
#   1. Client requests challenge for their pubkey.
#   2. Relay generates random challenge, stores it briefly in Redis.
#   3. Client signs (challenge || pubkey || timestamp) with their privkey.
#   4. Client sends signature back.
#   5. Relay verifies, issues short-lived session token.

CHALLENGE_BYTES = 32
CHALLENGE_TTL_SECONDS = 60


def generate_challenge() -> bytes:
    """Generate a fresh authentication challenge."""
    return nacl.utils.random(CHALLENGE_BYTES)


def build_auth_message(challenge: bytes, pubkey: bytes, timestamp: int) -> bytes:
    """
    Construct the message that a client signs during auth.

    Includes:
    - the challenge (binds to a specific server-issued challenge)
    - the pubkey (binds to a specific identity)
    - the timestamp (binds to a specific time, prevents long-lived replay)
    """
    if len(challenge) != CHALLENGE_BYTES:
        raise ValueError(f"Challenge must be {CHALLENGE_BYTES} bytes")
    if len(pubkey) != 32:
        raise ValueError("Pubkey must be 32 bytes")

    return canonical_json({
        "morok_auth": "v1",
        "challenge": challenge.hex(),
        "pubkey": pubkey.hex(),
        "timestamp": timestamp,
    })


def verify_auth_response(
    challenge: bytes,
    pubkey: bytes,
    timestamp: int,
    signature: bytes,
    *,
    max_age_seconds: int = CHALLENGE_TTL_SECONDS,
    now: int | None = None,
) -> bool:
    """
    Verify a client's auth response.

    Checks:
    1. Signature is valid for (challenge, pubkey, timestamp).
    2. Timestamp is recent (prevents replay of old responses).

    Caller must ALSO verify that the challenge was actually issued and
    has not been used before (one-time-use). That's a Redis lookup, not
    crypto.
    """
    import time

    now = now if now is not None else int(time.time())

    # Time bound check
    if abs(now - timestamp) > max_age_seconds:
        return False

    # Signature check
    message = build_auth_message(challenge, pubkey, timestamp)
    return ed25519_verify(message, signature, pubkey)


# ============================================================================
# ENVELOPE VERIFICATION (for incoming messages)
# ============================================================================
# Clients send messages as signed envelopes:
#   {
#     "from": "<sender_pubkey_hex>",
#     "to":   "<recipient_pubkey_hex>",
#     "ts":   <timestamp>,
#     "ttl":  <seconds>,
#     "blob": "<base64_encrypted_payload>",
#     "sig":  "<signature_over_canonical_envelope_minus_sig>"
#   }
# Relay verifies sig, then queues blob for delivery. Never decrypts.

@dataclass(frozen=True, slots=True)
class MessageEnvelope:
    sender_pubkey: bytes      # 32 bytes
    recipient_pubkey: bytes   # 32 bytes
    timestamp: int
    ttl_seconds: int
    blob: bytes               # opaque encrypted payload

    @property
    def envelope_id(self) -> str:
        """
        Deterministic ID for deduplication.

        Same (sender, recipient, timestamp, blob_hash) → same ID.
        Replays of the same message map to the same queue slot.
        """
        h = hashlib.sha256()
        h.update(self.sender_pubkey)
        h.update(self.recipient_pubkey)
        h.update(self.timestamp.to_bytes(8, "big"))
        h.update(hashlib.sha256(self.blob).digest())
        return h.hexdigest()


def verify_envelope_signature(
    envelope: dict[str, Any],
    *,
    max_age_seconds: int = 300,
    max_future_seconds: int = 60,
    now: int | None = None,
) -> tuple[bool, str | None]:
    """
    Verify a message envelope.

    Returns (is_valid, error_reason_if_invalid).

    Checks:
    1. All required fields present and well-formed.
    2. Timestamp in acceptable window (not too old, not too future).
    3. Signature valid for canonical envelope (minus 'sig' field).
    """
    import base64
    import time

    now = now if now is not None else int(time.time())

    required = {"from", "to", "ts", "ttl", "blob", "sig"}
    missing = required - envelope.keys()
    if missing:
        return False, f"missing fields: {sorted(missing)}"

    try:
        sender = bytes.fromhex(envelope["from"])
        recipient = bytes.fromhex(envelope["to"])
        timestamp = int(envelope["ts"])
        ttl = int(envelope["ttl"])
        blob = base64.b64decode(envelope["blob"], validate=True)
        signature = bytes.fromhex(envelope["sig"])
    except (ValueError, TypeError) as e:
        return False, f"malformed field: {e}"

    if len(sender) != 32 or len(recipient) != 32:
        return False, "invalid pubkey length"
    if len(signature) != 64:
        return False, "invalid signature length"
    if ttl <= 0:
        return False, "ttl must be positive"

    # Time window
    if timestamp < now - max_age_seconds:
        return False, "envelope too old"
    if timestamp > now + max_future_seconds:
        return False, "envelope from the future"

    # Signature check
    unsigned = {k: envelope[k] for k in envelope if k != "sig"}
    message = canonical_json(unsigned)
    if not ed25519_verify(message, signature, sender):
        return False, "signature invalid"

    return True, None


# ============================================================================
# UTILITY
# ============================================================================

def short_fingerprint(pubkey: bytes, segments: int = 6) -> str:
    """
    Display-friendly short fingerprint of a pubkey.

    Used in UI: "9f2a · 4c7b · 1e8d · 6f3a · 2b5c · 8e1f"

    Not cryptographically meaningful — just a way to glance at a pubkey
    without showing all 64 hex chars. Full pubkey is what matters for security;
    short fingerprints are convenience only.
    """
    if len(pubkey) != 32:
        raise ValueError("Pubkey must be 32 bytes")
    full = pubkey.hex()
    return " · ".join(full[i * 4 : i * 4 + 4] for i in range(segments))


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time bytes comparison. Use for comparing tokens/secrets
    to avoid timing attacks.
    """
    return secrets.compare_digest(a, b)
