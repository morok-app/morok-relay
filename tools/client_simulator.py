"""
Morok end-to-end test client.

Simulates real clients to verify the relay's full message flow:

    1.  GET /health
    2.  Auth (challenge + verify)
    3.  GET /me
    4.  Claim @username
    5.  Send envelope to SELF
    6.  List inbox
    7.  Fetch blob
    8.  ACK envelope
    9.  WebSocket inbox — connect, receive push, ack

   Group flow (v0.7):
   10.  Spin up a SECOND identity (alice → bob)
   11.  Alice creates a group, encrypts a name client-side
   12.  Alice adds Bob as a member
   13.  Alice posts a group message
   14.  Bob lists inbox — should see the group envelope (to=group_id)
   15.  Bob fetches the blob — bytes match what Alice sent
   16.  Alice deletes the group (cleanup)

   17.  Release @username (cleanup)

Usage:
    python tools/client_simulator.py [--relay https://relay1.morok.app]
    python tools/client_simulator.py --relay http://localhost:8000

Requirements:
    pip install httpx websockets pynacl
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import secrets
import sys
import time

import httpx
import nacl.signing
import websockets

DEFAULT_RELAY = "https://relay1.morok.app"
USERNAME_PREFIX = "tst"


# ============================================================================
# Crypto helpers (must mirror server side exactly)
# ============================================================================

def canonical_json(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def build_auth_message(challenge: bytes, pubkey: bytes, timestamp: int) -> bytes:
    return canonical_json({
        "morok_auth": "v1",
        "challenge": challenge.hex(),
        "pubkey": pubkey.hex(),
        "timestamp": timestamp,
    })


def build_envelope_to_pubkey(
    sender_sk: nacl.signing.SigningKey,
    recipient_pubkey: bytes,
    blob: bytes,
    ttl_seconds: int = 3600,
) -> dict:
    """1-on-1 envelope."""
    sender_pubkey = bytes(sender_sk.verify_key)
    ts = int(time.time())
    unsigned = {
        "from": sender_pubkey.hex(),
        "to": recipient_pubkey.hex(),
        "ts": ts,
        "ttl": ttl_seconds,
        "blob": base64.b64encode(blob).decode(),
    }
    signature = sender_sk.sign(canonical_json(unsigned)).signature
    return {**unsigned, "sig": signature.hex()}


def build_group_envelope(
    sender_sk: nacl.signing.SigningKey,
    group_id: str,
    blob: bytes,
    ttl_seconds: int = 3600,
) -> dict:
    """Group envelope: 'to' is group UUID string."""
    sender_pubkey = bytes(sender_sk.verify_key)
    ts = int(time.time())
    unsigned = {
        "from": sender_pubkey.hex(),
        "to": group_id,
        "ts": ts,
        "ttl": ttl_seconds,
        "blob": base64.b64encode(blob).decode(),
    }
    signature = sender_sk.sign(canonical_json(unsigned)).signature
    return {**unsigned, "sig": signature.hex()}


# ============================================================================
# Output helpers
# ============================================================================

OK = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
INFO = "\033[94mi\033[0m"


def step(label: str):
    print(f"\n{INFO} {label}")


def passed(msg: str):
    print(f"  {OK} {msg}")


def failed(msg: str):
    print(f"  {FAIL} {msg}")


# ============================================================================
# Identity helper
# ============================================================================

class Identity:
    """One simulated client identity: keypair + session token."""

    def __init__(self, label: str):
        self.label = label
        self.sk = nacl.signing.SigningKey.generate()
        self.pubkey = bytes(self.sk.verify_key)
        self.session_token: str | None = None

    @property
    def short_pubkey(self) -> str:
        return self.pubkey.hex()[:16]

    @property
    def auth_header(self) -> dict:
        if not self.session_token:
            return {}
        return {"Authorization": f"Bearer {self.session_token}"}


async def login(http: httpx.AsyncClient, relay_url: str, identity: Identity) -> bool:
    """Run challenge → verify for an identity. Sets identity.session_token."""
    try:
        r = await http.post(
            f"{relay_url}/api/v1/auth/challenge",
            json={"pubkey_hex": identity.pubkey.hex()},
        )
        r.raise_for_status()
        challenge_hex = r.json()["challenge_hex"]
    except Exception as e:
        failed(f"{identity.label}: challenge failed: {e}")
        return False

    ts = int(time.time())
    msg = build_auth_message(bytes.fromhex(challenge_hex), identity.pubkey, ts)
    signature = identity.sk.sign(msg).signature

    try:
        r = await http.post(
            f"{relay_url}/api/v1/auth/verify",
            json={
                "pubkey_hex": identity.pubkey.hex(),
                "challenge_hex": challenge_hex,
                "timestamp": ts,
                "signature_hex": signature.hex(),
            },
        )
        r.raise_for_status()
        identity.session_token = r.json()["session_token"]
        return True
    except Exception as e:
        failed(f"{identity.label}: verify failed: {e}")
        return False


# ============================================================================
# Test runner
# ============================================================================

class TestClient:
    def __init__(self, relay_url: str):
        self.relay_url = relay_url.rstrip("/")
        self.ws_url = (
            self.relay_url
            .replace("https://", "wss://")
            .replace("http://", "ws://")
        )
        self.alice = Identity("alice")
        self.bob = Identity("bob")
        self.username: str | None = None
        self.failures = 0

    async def run(self) -> int:
        print(f"{INFO} Testing relay: {self.relay_url}")
        print(f"{INFO} alice pubkey: {self.alice.short_pubkey}...")
        print(f"{INFO} bob   pubkey: {self.bob.short_pubkey}...")

        async with httpx.AsyncClient(timeout=10.0) as http:
            await self._step_health(http)
            await self._step_auth(http)
            await self._step_get_me(http)
            await self._step_claim_username(http)
            await self._step_send_envelope_to_self(http)
            await self._step_list_inbox(http)
            envelope_id = await self._step_fetch_blob(http)
            if envelope_id:
                await self._step_ack(http, envelope_id)
            await self._step_websocket(http)

            # Group flow
            await self._step_login_bob(http)
            group_id = await self._step_create_group(http)
            if group_id:
                await self._step_add_member(http, group_id)
                msg_envelope_id = await self._step_send_group_message(http, group_id)
                if msg_envelope_id:
                    await self._step_bob_receives_group(http, msg_envelope_id)
                await self._step_delete_group(http, group_id)

            await self._step_release_username(http)

        print()
        if self.failures == 0:
            print(f"{OK} All steps passed.")
            return 0
        print(f"{FAIL} {self.failures} step(s) failed.")
        return 1

    # ----- 1-on-1 steps (unchanged from v0.5) -----

    async def _step_health(self, http: httpx.AsyncClient):
        step("1. GET /health")
        try:
            r = await http.get(f"{self.relay_url}/health")
            r.raise_for_status()
            data = r.json()
            assert data["status"] == "ok"
            passed(f"status=ok, version={data['version']}, relay={data['relay_name']}")
        except Exception as e:
            failed(f"health check failed: {e}")
            self.failures += 1

    async def _step_auth(self, http: httpx.AsyncClient):
        step("2. Auth (challenge + verify) — alice")
        ok = await login(http, self.relay_url, self.alice)
        if ok:
            passed(f"got session token: {self.alice.session_token[:16]}...")
        else:
            self.failures += 1

    async def _step_get_me(self, http: httpx.AsyncClient):
        step("3. GET /me")
        try:
            r = await http.get(
                f"{self.relay_url}/api/v1/users/me",
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            data = r.json()
            assert data["pubkey_hex"] == self.alice.pubkey.hex()
            assert data["username"] is None
            assert data["tier"] == "free"
            passed(f"tier={data['tier']}, no username yet")
        except Exception as e:
            failed(f"/me failed: {e}")
            self.failures += 1

    async def _step_claim_username(self, http: httpx.AsyncClient):
        step("4. Claim @username")
        suffix = secrets.token_hex(2)[:2]
        self.username = f"{USERNAME_PREFIX}{suffix}"
        try:
            r = await http.post(
                f"{self.relay_url}/api/v1/users/me/username",
                json={"username": self.username},
                headers=self.alice.auth_header,
            )
            if r.status_code == 409:
                self.username = f"{USERNAME_PREFIX}{secrets.token_hex(2)[:2]}"
                r = await http.post(
                    f"{self.relay_url}/api/v1/users/me/username",
                    json={"username": self.username},
                    headers=self.alice.auth_header,
                )
            r.raise_for_status()
            data = r.json()
            assert data["username"] == self.username
            passed(f"claimed @{self.username}")
        except Exception as e:
            failed(f"username claim failed: {e}")
            if isinstance(e, httpx.HTTPStatusError):
                failed(f"  response: {e.response.text}")
            self.failures += 1

    async def _step_send_envelope_to_self(self, http: httpx.AsyncClient):
        step("5. Send envelope to self")
        self.test_payload = b"hello morok " + secrets.token_bytes(16)
        envelope = build_envelope_to_pubkey(
            self.alice.sk, self.alice.pubkey, self.test_payload, 3600
        )
        try:
            r = await http.post(
                f"{self.relay_url}/api/v1/messages",
                json=envelope,
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            data = r.json()
            self.envelope_id = data["envelope_id"]
            assert data["queued"] is True
            passed(f"queued: {self.envelope_id[:16]}...")
        except Exception as e:
            failed(f"send failed: {e}")
            if isinstance(e, httpx.HTTPStatusError):
                failed(f"  response: {e.response.text}")
            self.failures += 1
            self.envelope_id = None

    async def _step_list_inbox(self, http: httpx.AsyncClient):
        step("6. List inbox")
        try:
            r = await http.get(
                f"{self.relay_url}/api/v1/messages",
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            data = r.json()
            found = any(
                e["envelope_id"] == getattr(self, "envelope_id", None)
                for e in data["envelopes"]
            )
            if found:
                passed(f"found our envelope ({data['count']} total)")
            else:
                failed(f"our envelope not in inbox — {data['count']} others")
                self.failures += 1
        except Exception as e:
            failed(f"list failed: {e}")
            self.failures += 1

    async def _step_fetch_blob(self, http: httpx.AsyncClient) -> str | None:
        step("7. Fetch blob")
        if not getattr(self, "envelope_id", None):
            failed("no envelope_id")
            self.failures += 1
            return None
        try:
            r = await http.get(
                f"{self.relay_url}/api/v1/messages/{self.envelope_id}",
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            if r.content == self.test_payload:
                passed(f"bytes match ({len(r.content)} bytes)")
                return self.envelope_id
            failed(f"mismatch: got {len(r.content)} expected {len(self.test_payload)}")
            self.failures += 1
            return None
        except Exception as e:
            failed(f"fetch failed: {e}")
            self.failures += 1
            return None

    async def _step_ack(self, http: httpx.AsyncClient, envelope_id: str):
        step("8. ACK envelope")
        try:
            r = await http.delete(
                f"{self.relay_url}/api/v1/messages/{envelope_id}",
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            passed("acknowledged")
        except Exception as e:
            failed(f"ack failed: {e}")
            self.failures += 1

    async def _step_websocket(self, http: httpx.AsyncClient):
        step("9. WebSocket inbox — connect, receive push, ack")
        if not self.alice.session_token:
            failed("no session token")
            self.failures += 1
            return
        ws_endpoint = f"{self.ws_url}/ws/v1/inbox?token={self.alice.session_token}"
        try:
            async with websockets.connect(ws_endpoint) as ws:
                passed("connected")
                raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
                catchup = json.loads(raw)
                assert catchup["type"] == "catchup"
                passed(f"catchup ({catchup['count']} pending)")

                payload2 = b"ws-push-test " + secrets.token_bytes(8)
                env2 = build_envelope_to_pubkey(
                    self.alice.sk, self.alice.pubkey, payload2, 600
                )
                r = await http.post(
                    f"{self.relay_url}/api/v1/messages",
                    json=env2,
                    headers=self.alice.auth_header,
                )
                r.raise_for_status()
                env2_id = r.json()["envelope_id"]

                got_new = False
                deadline = asyncio.get_event_loop().time() + 5.0
                while asyncio.get_event_loop().time() < deadline:
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=1.0)
                        frame = json.loads(raw)
                        if frame.get("type") == "new" and frame.get("envelope", {}).get("envelope_id") == env2_id:
                            got_new = True
                            break
                    except asyncio.TimeoutError:
                        continue

                if got_new:
                    passed("received real-time push")
                else:
                    failed("no push within 5s")
                    self.failures += 1

                await ws.send(json.dumps({"type": "ack", "envelope_id": env2_id}))
                passed("ack sent")
        except Exception as e:
            failed(f"WebSocket failed: {e}")
            self.failures += 1

    # ----- Group flow (new in v0.7) -----

    async def _step_login_bob(self, http: httpx.AsyncClient):
        step("10. Bob logs in (second identity)")
        ok = await login(http, self.relay_url, self.bob)
        if ok:
            passed(f"bob session: {self.bob.session_token[:16]}...")
            # Also call /me so the user row is created on the relay side
            try:
                r = await http.get(
                    f"{self.relay_url}/api/v1/users/me",
                    headers=self.bob.auth_header,
                )
                r.raise_for_status()
                passed(f"bob /me ok (tier={r.json()['tier']})")
            except Exception as e:
                failed(f"bob /me failed: {e}")
                self.failures += 1
        else:
            self.failures += 1

    async def _step_create_group(self, http: httpx.AsyncClient) -> str | None:
        step("11. Alice creates a group")
        # name_encrypted is opaque to the server — for the test we just
        # send some random bytes that look like ciphertext
        fake_encrypted_name = b"\x00\x01\x02\x03" + secrets.token_bytes(64)
        try:
            r = await http.post(
                f"{self.relay_url}/api/v1/groups",
                json={
                    "name_encrypted": base64.b64encode(fake_encrypted_name).decode(),
                    "is_channel": False,
                    "default_ttl_seconds": 3600,
                    "anonymous_senders": False,
                },
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            data = r.json()
            group_id = data["group_id"]
            assert data["max_members"] == 50  # free tier
            assert len(data["members"]) == 1
            assert data["members"][0]["is_admin"] is True
            passed(f"group_id={group_id[:8]}..., alice is admin")
            return group_id
        except Exception as e:
            failed(f"create group failed: {e}")
            if isinstance(e, httpx.HTTPStatusError):
                failed(f"  response: {e.response.text}")
            self.failures += 1
            return None

    async def _step_add_member(self, http: httpx.AsyncClient, group_id: str):
        step("12. Alice adds Bob as a member")
        try:
            r = await http.post(
                f"{self.relay_url}/api/v1/groups/{group_id}/members",
                json={"pubkey_hex": self.bob.pubkey.hex()},
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            data = r.json()
            assert data["action"] == "added"
            assert data["member_count"] == 2
            passed(f"Bob added, member_count={data['member_count']}")
        except Exception as e:
            failed(f"add member failed: {e}")
            if isinstance(e, httpx.HTTPStatusError):
                failed(f"  response: {e.response.text}")
            self.failures += 1

    async def _step_send_group_message(
        self, http: httpx.AsyncClient, group_id: str
    ) -> str | None:
        step("13. Alice posts a message to the group")
        self.group_payload = b"group hello " + secrets.token_bytes(16)
        envelope = build_group_envelope(
            self.alice.sk, group_id, self.group_payload, 3600
        )
        try:
            r = await http.post(
                f"{self.relay_url}/api/v1/groups/{group_id}/messages",
                json=envelope,
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            data = r.json()
            assert data["queued"] is True
            assert data["recipient_count"] == 2  # alice + bob
            passed(f"queued, fan-out to {data['recipient_count']} members")
            return data["envelope_id"]
        except Exception as e:
            failed(f"group send failed: {e}")
            if isinstance(e, httpx.HTTPStatusError):
                failed(f"  response: {e.response.text}")
            self.failures += 1
            return None

    async def _step_bob_receives_group(
        self, http: httpx.AsyncClient, envelope_id: str
    ):
        step("14. Bob lists inbox and fetches blob")
        # 14a: list
        try:
            r = await http.get(
                f"{self.relay_url}/api/v1/messages",
                headers=self.bob.auth_header,
            )
            r.raise_for_status()
            data = r.json()
            found = next(
                (e for e in data["envelopes"] if e["envelope_id"] == envelope_id),
                None,
            )
            if found is None:
                failed(f"group message not in Bob's inbox ({data['count']} others)")
                self.failures += 1
                return
            # Metadata should show group_id (broadcast 'to' value)
            assert found.get("group_id") is not None
            passed(f"Bob sees group msg in inbox (group_id={found['group_id'][:8]}...)")
        except Exception as e:
            failed(f"bob list failed: {e}")
            self.failures += 1
            return

        # 14b: fetch
        try:
            r = await http.get(
                f"{self.relay_url}/api/v1/messages/{envelope_id}",
                headers=self.bob.auth_header,
            )
            r.raise_for_status()
            if r.content == self.group_payload:
                passed(f"Bob fetched blob, bytes match ({len(r.content)})")
            else:
                failed(f"blob mismatch: got {len(r.content)} expected {len(self.group_payload)}")
                self.failures += 1
        except Exception as e:
            failed(f"bob fetch failed: {e}")
            self.failures += 1

    async def _step_delete_group(self, http: httpx.AsyncClient, group_id: str):
        step("15. Alice deletes the group (cleanup)")
        try:
            r = await http.delete(
                f"{self.relay_url}/api/v1/groups/{group_id}",
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            data = r.json()
            assert data["deleted"] is True
            passed("group deleted")
        except Exception as e:
            failed(f"delete group failed: {e}")
            self.failures += 1

    async def _step_release_username(self, http: httpx.AsyncClient):
        step("16. Release @username (cleanup)")
        try:
            r = await http.delete(
                f"{self.relay_url}/api/v1/users/me/username",
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            passed("released")
        except Exception as e:
            failed(f"release failed: {e}")
            self.failures += 1


# ============================================================================
# CLI entry
# ============================================================================

async def main():
    p = argparse.ArgumentParser(description="Morok end-to-end test client")
    p.add_argument(
        "--relay",
        default=DEFAULT_RELAY,
        help=f"Relay URL (default: {DEFAULT_RELAY})",
    )
    args = p.parse_args()
    client = TestClient(args.relay)
    return await client.run()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
