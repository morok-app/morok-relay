"""
Tests for morok_relay.crypto.

These are critical — if crypto is wrong, the whole server is broken.
We test:
- Ed25519 round-trip (sign → verify)
- Bad signature rejection (wrong key, tampered message, malformed sig)
- Canonical serialization determinism
- Challenge-response auth flow
- Envelope verification (good and bad cases)

Run: pytest tests/test_crypto.py -v
"""
from __future__ import annotations

import base64
import time

import pytest

from morok_relay.crypto import (
    CHALLENGE_BYTES,
    Ed25519Keypair,
    build_auth_message,
    canonical_json,
    constant_time_compare,
    ed25519_sign,
    ed25519_verify,
    generate_challenge,
    short_fingerprint,
    verify_auth_response,
    verify_envelope_signature,
    x25519_pubkey_from_ed25519,
)


# ============================================================================
# CANONICAL JSON
# ============================================================================

class TestCanonicalJSON:
    def test_basic(self):
        assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'

    def test_unicode_preserved(self):
        out = canonical_json({"name": "Леся"})
        assert out == '{"name":"Леся"}'.encode("utf-8")

    def test_no_whitespace(self):
        assert b" " not in canonical_json({"a": 1, "b": [1, 2, 3]})

    def test_nested_sorted(self):
        out = canonical_json({"x": {"b": 2, "a": 1}})
        assert out == b'{"x":{"a":1,"b":2}}'

    def test_nan_rejected(self):
        with pytest.raises(ValueError):
            canonical_json({"x": float("nan")})

    def test_determinism(self):
        """Same input → same output, every time."""
        obj = {"timestamp": 1234, "data": [3, 1, 2], "nested": {"z": 1, "a": 2}}
        outs = {canonical_json(obj) for _ in range(50)}
        assert len(outs) == 1


# ============================================================================
# Ed25519
# ============================================================================

class TestEd25519:
    def test_keypair_generate(self):
        kp = Ed25519Keypair.generate()
        assert len(kp.public_key) == 32
        assert len(kp.private_key) == 32

    def test_keypair_from_seed_deterministic(self):
        seed = b"\x42" * 32
        kp1 = Ed25519Keypair.from_seed(seed)
        kp2 = Ed25519Keypair.from_seed(seed)
        assert kp1.public_key == kp2.public_key
        assert kp1.private_key == kp2.private_key

    def test_keypair_from_seed_wrong_length(self):
        with pytest.raises(ValueError):
            Ed25519Keypair.from_seed(b"too short")

    def test_sign_verify_roundtrip(self):
        kp = Ed25519Keypair.generate()
        msg = b"hello morok"
        sig = ed25519_sign(msg, kp.private_key)
        assert len(sig) == 64
        assert ed25519_verify(msg, sig, kp.public_key) is True

    def test_verify_wrong_key(self):
        kp1 = Ed25519Keypair.generate()
        kp2 = Ed25519Keypair.generate()
        msg = b"hello"
        sig = ed25519_sign(msg, kp1.private_key)
        # Sig from kp1 must not verify against kp2
        assert ed25519_verify(msg, sig, kp2.public_key) is False

    def test_verify_tampered_message(self):
        kp = Ed25519Keypair.generate()
        sig = ed25519_sign(b"hello", kp.private_key)
        assert ed25519_verify(b"hellp", sig, kp.public_key) is False

    def test_verify_empty_signature_fails(self):
        """
        Critical regression test: lac_crypto.py:148 returned True for missing
        sig. We must return False.
        """
        kp = Ed25519Keypair.generate()
        assert ed25519_verify(b"hello", b"", kp.public_key) is False
        assert ed25519_verify(b"hello", b"\x00" * 64, kp.public_key) is False

    def test_verify_empty_pubkey_fails(self):
        assert ed25519_verify(b"hello", b"\x00" * 64, b"") is False

    def test_verify_wrong_signature_length(self):
        kp = Ed25519Keypair.generate()
        assert ed25519_verify(b"hello", b"\x00" * 32, kp.public_key) is False
        assert ed25519_verify(b"hello", b"\x00" * 100, kp.public_key) is False

    def test_verify_wrong_pubkey_length(self):
        kp = Ed25519Keypair.generate()
        sig = ed25519_sign(b"hello", kp.private_key)
        assert ed25519_verify(b"hello", sig, b"\x00" * 16) is False


# ============================================================================
# X25519 derivation
# ============================================================================

class TestX25519Derivation:
    def test_x25519_pubkey_deterministic(self):
        kp = Ed25519Keypair.generate()
        a = x25519_pubkey_from_ed25519(kp.public_key)
        b = x25519_pubkey_from_ed25519(kp.public_key)
        assert a == b
        assert len(a) == 32

    def test_x25519_pubkey_different_per_identity(self):
        kp1 = Ed25519Keypair.generate()
        kp2 = Ed25519Keypair.generate()
        a = x25519_pubkey_from_ed25519(kp1.public_key)
        b = x25519_pubkey_from_ed25519(kp2.public_key)
        assert a != b

    def test_x25519_wrong_length(self):
        with pytest.raises(ValueError):
            x25519_pubkey_from_ed25519(b"too short")


# ============================================================================
# CHALLENGE-RESPONSE AUTH
# ============================================================================

class TestAuthFlow:
    def test_challenge_size(self):
        ch = generate_challenge()
        assert len(ch) == CHALLENGE_BYTES

    def test_challenges_are_random(self):
        challenges = {generate_challenge() for _ in range(100)}
        assert len(challenges) == 100  # all unique

    def test_full_auth_flow_succeeds(self):
        kp = Ed25519Keypair.generate()
        challenge = generate_challenge()
        ts = int(time.time())

        message = build_auth_message(challenge, kp.public_key, ts)
        signature = ed25519_sign(message, kp.private_key)

        assert verify_auth_response(
            challenge, kp.public_key, ts, signature, now=ts
        ) is True

    def test_auth_fails_wrong_signer(self):
        kp_real = Ed25519Keypair.generate()
        kp_attacker = Ed25519Keypair.generate()
        challenge = generate_challenge()
        ts = int(time.time())

        message = build_auth_message(challenge, kp_real.public_key, ts)
        # Attacker tries to claim kp_real's identity but signs with their own key
        bad_signature = ed25519_sign(message, kp_attacker.private_key)

        assert verify_auth_response(
            challenge, kp_real.public_key, ts, bad_signature, now=ts
        ) is False

    def test_auth_fails_old_timestamp(self):
        kp = Ed25519Keypair.generate()
        challenge = generate_challenge()
        ts = int(time.time()) - 3600  # 1 hour ago
        now = int(time.time())

        message = build_auth_message(challenge, kp.public_key, ts)
        signature = ed25519_sign(message, kp.private_key)

        assert verify_auth_response(
            challenge, kp.public_key, ts, signature, now=now
        ) is False

    def test_auth_fails_replay_with_different_challenge(self):
        kp = Ed25519Keypair.generate()
        challenge1 = generate_challenge()
        challenge2 = generate_challenge()
        ts = int(time.time())

        # Sign challenge1
        message = build_auth_message(challenge1, kp.public_key, ts)
        signature = ed25519_sign(message, kp.private_key)

        # Try to use that signature for challenge2 — must fail
        assert verify_auth_response(
            challenge2, kp.public_key, ts, signature, now=ts
        ) is False


# ============================================================================
# ENVELOPE VERIFICATION
# ============================================================================

def _make_envelope(sender_kp, recipient_kp, *, ts=None, ttl=3600, blob=b"encrypted"):
    """Helper: build a properly-signed envelope dict for tests."""
    ts = ts if ts is not None else int(time.time())
    unsigned = {
        "from": sender_kp.public_key.hex(),
        "to": recipient_kp.public_key.hex(),
        "ts": ts,
        "ttl": ttl,
        "blob": base64.b64encode(blob).decode(),
    }
    sig = ed25519_sign(canonical_json(unsigned), sender_kp.private_key)
    return {**unsigned, "sig": sig.hex()}


class TestEnvelope:
    def test_valid_envelope(self):
        sender = Ed25519Keypair.generate()
        recipient = Ed25519Keypair.generate()
        env = _make_envelope(sender, recipient)
        ok, err = verify_envelope_signature(env)
        assert ok is True, err

    def test_missing_field(self):
        sender = Ed25519Keypair.generate()
        recipient = Ed25519Keypair.generate()
        env = _make_envelope(sender, recipient)
        del env["sig"]
        ok, err = verify_envelope_signature(env)
        assert ok is False
        assert "missing" in err

    def test_tampered_blob(self):
        sender = Ed25519Keypair.generate()
        recipient = Ed25519Keypair.generate()
        env = _make_envelope(sender, recipient)
        # Mutate blob — signature should no longer match
        env["blob"] = base64.b64encode(b"different").decode()
        ok, err = verify_envelope_signature(env)
        assert ok is False
        assert "signature" in err.lower()

    def test_tampered_recipient(self):
        """Sneak attempt: change recipient after signing."""
        sender = Ed25519Keypair.generate()
        recipient = Ed25519Keypair.generate()
        attacker = Ed25519Keypair.generate()
        env = _make_envelope(sender, recipient)
        env["to"] = attacker.public_key.hex()
        ok, err = verify_envelope_signature(env)
        assert ok is False

    def test_too_old(self):
        sender = Ed25519Keypair.generate()
        recipient = Ed25519Keypair.generate()
        env = _make_envelope(sender, recipient, ts=int(time.time()) - 3600)
        ok, err = verify_envelope_signature(env)
        assert ok is False
        assert "old" in err

    def test_too_future(self):
        sender = Ed25519Keypair.generate()
        recipient = Ed25519Keypair.generate()
        env = _make_envelope(sender, recipient, ts=int(time.time()) + 3600)
        ok, err = verify_envelope_signature(env)
        assert ok is False
        assert "future" in err

    def test_malformed_pubkey(self):
        sender = Ed25519Keypair.generate()
        recipient = Ed25519Keypair.generate()
        env = _make_envelope(sender, recipient)
        env["from"] = "not_hex"
        ok, err = verify_envelope_signature(env)
        assert ok is False


# ============================================================================
# UTILITIES
# ============================================================================

class TestUtilities:
    def test_short_fingerprint_format(self):
        pk = bytes.fromhex("9f2a4c7b1e8d6f3a2b5c8e1f7d4a9c2e5b8a3f6c1d9e4b7a2c5f8d1e6b3a9c4f")
        fp = short_fingerprint(pk)
        assert fp == "9f2a · 4c7b · 1e8d · 6f3a · 2b5c · 8e1f"

    def test_short_fingerprint_wrong_length(self):
        with pytest.raises(ValueError):
            short_fingerprint(b"short")

    def test_constant_time_compare(self):
        assert constant_time_compare(b"abc", b"abc") is True
        assert constant_time_compare(b"abc", b"abd") is False
        assert constant_time_compare(b"abc", b"abcd") is False
