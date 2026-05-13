"""
Morok end-to-end test client.

Simulates a real client to verify the relay's full message flow:

    1. Generate Ed25519 keypair
    2. Request auth challenge
    3. Sign + verify  →  session token
    4. GET /me        →  confirm account created
    5. Claim @username
    6. Send envelope to SELF
    7. List inbox     →  should see our envelope
    8. Fetch blob     →  bytes match what we sent
    9. ACK envelope   →  removed from inbox
   10. Connect WebSocket inbox, send another envelope, confirm push

If any step fails, prints what went wrong and exits non-zero.

Usage:
    python tools/client_simulator.py [--relay https://relay1.morok.app]
    python tools/client_simulator.py --relay http://localhost:8000  # local dev

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
# Use a 5-character username to satisfy free tier (default for new accounts).
# Random suffix so reruns don't conflict.
USERNAME_PREFIX = "tst"


# ============================================================================
# Crypto helpers (mirror morok_relay.crypto exactly)
# ============================================================================

def canonical_json(obj) -> bytes:
    """Same canonical form as server expects."""
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


def build_envelope(
    sender_sk: nacl.signing.SigningKey,
    recipient_pubkey: bytes,
    blob: bytes,
    ttl_seconds: int = 3600,
) -> dict:
    """Build a signed envelope as a client would."""
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


# ============================================================================
# Test colour output
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
# Test runner
# ============================================================================

class TestClient:
    def __init__(self, relay_url: str):
        self.relay_url = relay_url.rstrip("/")
        # WebSocket URL: swap https:// → wss:// (and http → ws)
        self.ws_url = (
            self.relay_url
            .replace("https://", "wss://")
            .replace("http://", "ws://")
        )
        self.sk = nacl.signing.SigningKey.generate()
        self.pubkey = bytes(self.sk.verify_key)
        self.session_token: str | None = None
        self.username: str | None = None
        self.failures = 0

    @property
    def auth_header(self) -> dict:
        if not self.session_token:
            return {}
        return {"Authorization": f"Bearer {self.session_token}"}

    async def run(self) -> int:
        print(f"{INFO} Testing relay: {self.relay_url}")
        print(f"{INFO} Generated keypair, pubkey: {self.pubkey.hex()[:16]}...")

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
            await self._step_release_username(http)

        print()
        if self.failures == 0:
            print(f"{OK} All steps passed.")
            return 0
        print(f"{FAIL} {self.failures} step(s) failed.")
        return 1

    # ----- Steps -----

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
        step("2. Auth (challenge + verify)")
        try:
            r = await http.post(
                f"{self.relay_url}/api/v1/auth/challenge",
                json={"pubkey_hex": self.pubkey.hex()},
            )
            r.raise_for_status()
            challenge_hex = r.json()["challenge_hex"]
            passed(f"got challenge: {challenge_hex[:16]}...")
        except Exception as e:
            failed(f"challenge request failed: {e}")
            self.failures += 1
            return

        # Sign it
        ts = int(time.time())
        msg = build_auth_message(bytes.fromhex(challenge_hex), self.pubkey, ts)
        signature = self.sk.sign(msg).signature

        try:
            r = await http.post(
                f"{self.relay_url}/api/v1/auth/verify",
                json={
                    "pubkey_hex": self.pubkey.hex(),
                    "challenge_hex": challenge_hex,
                    "timestamp": ts,
                    "signature_hex": signature.hex(),
                },
            )
            r.raise_for_status()
            data = r.json()
            self.session_token = data["session_token"]
            assert data["pubkey_hex"] == self.pubkey.hex()
            passed(f"got session token: {self.session_token[:16]}...")
        except Exception as e:
            failed(f"verify failed: {e}")
            self.failures += 1

    async def _step_get_me(self, http: httpx.AsyncClient):
        step("3. GET /me")
        try:
            r = await http.get(
                f"{self.relay_url}/api/v1/users/me",
                headers=self.auth_header,
            )
            r.raise_for_status()
            data = r.json()
            assert data["pubkey_hex"] == self.pubkey.hex()
            assert data["username"] is None
            assert data["tier"] == "free"
            passed(f"tier={data['tier']}, no username yet")
        except Exception as e:
            failed(f"/me failed: {e}")
            self.failures += 1

    async def _step_claim_username(self, http: httpx.AsyncClient):
        step("4. Claim @username")
        # 5-char username (passes free tier minimum)
        suffix = secrets.token_hex(2)[:2]  # 2 random hex digits
        self.username = f"{USERNAME_PREFIX}{suffix}"
        try:
            r = await http.post(
                f"{self.relay_url}/api/v1/users/me/username",
                json={"username": self.username},
                headers=self.auth_header,
            )
            if r.status_code == 409:
                # Cooldown or collision — try once more with new suffix
                self.username = f"{USERNAME_PREFIX}{secrets.token_hex(2)[:2]}"
                r = await http.post(
                    f"{self.relay_url}/api/v1/users/me/username",
                    json={"username": self.username},
                    headers=self.auth_header,
                )
            r.raise_for_status()
            data = r.json()
            assert data["username"] == self.username
            passed(f"claimed @{self.username}")
        except Exception as e:
            failed(f"username claim failed: {e}")
            if isinstance(e, httpx.HTTPStatusError):
                failed(f"  response body: {e.response.text}")
            self.failures += 1

    async def _step_send_envelope_to_self(self, http: httpx.AsyncClient):
        step("5. Send envelope to self")
        self.test_payload = b"hello, this is morok end-to-end test " + secrets.token_bytes(16)
        envelope = build_envelope(
            sender_sk=self.sk,
            recipient_pubkey=self.pubkey,  # self
            blob=self.test_payload,
            ttl_seconds=3600,
        )
        try:
            r = await http.post(
                f"{self.relay_url}/api/v1/messages",
                json=envelope,
                headers=self.auth_header,
            )
            r.raise_for_status()
            data = r.json()
            self.envelope_id = data["envelope_id"]
            assert data["queued"] is True
            passed(f"queued envelope: {self.envelope_id[:16]}...")
        except Exception as e:
            failed(f"send failed: {e}")
            if isinstance(e, httpx.HTTPStatusError):
                failed(f"  response body: {e.response.text}")
            self.failures += 1
            self.envelope_id = None

    async def _step_list_inbox(self, http: httpx.AsyncClient):
        step("6. List inbox")
        try:
            r = await http.get(
                f"{self.relay_url}/api/v1/messages",
                headers=self.auth_header,
            )
            r.raise_for_status()
            data = r.json()
            assert data["count"] >= 1
            found = any(
                e["envelope_id"] == getattr(self, "envelope_id", None)
                for e in data["envelopes"]
            )
            if found:
                passed(f"found our envelope in inbox ({data['count']} total)")
            else:
                failed(f"our envelope not in inbox — got {data['count']} others")
                self.failures += 1
        except Exception as e:
            failed(f"list failed: {e}")
            self.failures += 1

    async def _step_fetch_blob(self, http: httpx.AsyncClient) -> str | None:
        step("7. Fetch blob")
        if not getattr(self, "envelope_id", None):
            failed("no envelope_id from previous step")
            self.failures += 1
            return None
        try:
            r = await http.get(
                f"{self.relay_url}/api/v1/messages/{self.envelope_id}",
                headers=self.auth_header,
            )
            r.raise_for_status()
            fetched = r.content
            if fetched == self.test_payload:
                passed(f"blob bytes match ({len(fetched)} bytes)")
                return self.envelope_id
            else:
                failed(f"blob mismatch — got {len(fetched)} bytes, expected {len(self.test_payload)}")
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
                headers=self.auth_header,
            )
            r.raise_for_status()
            data = r.json()
            assert data["acknowledged"] is True
            passed("acknowledged")
        except Exception as e:
            failed(f"ack failed: {e}")
            self.failures += 1

    async def _step_websocket(self, http: httpx.AsyncClient):
        step("9. WebSocket inbox — connect, receive push, ack")
        if not self.session_token:
            failed("no session token")
            self.failures += 1
            return

        ws_endpoint = f"{self.ws_url}/ws/v1/inbox?token={self.session_token}"

        try:
            async with websockets.connect(ws_endpoint) as ws:
                passed("connected")

                # 1. Receive catchup frame
                raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
                catchup = json.loads(raw)
                assert catchup["type"] == "catchup"
                passed(f"got catchup frame ({catchup['count']} pending)")

                # 2. Send ourselves another envelope via REST
                payload2 = b"ws-push-test " + secrets.token_bytes(8)
                env2 = build_envelope(
                    sender_sk=self.sk,
                    recipient_pubkey=self.pubkey,
                    blob=payload2,
                    ttl_seconds=600,
                )
                r = await http.post(
                    f"{self.relay_url}/api/v1/messages",
                    json=env2,
                    headers=self.auth_header,
                )
                r.raise_for_status()
                env2_id = r.json()["envelope_id"]

                # 3. Expect a "new" frame on the WebSocket
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
                    passed("received real-time push notification")
                else:
                    failed("did not receive push within 5s")
                    self.failures += 1

                # 4. ACK over WebSocket
                await ws.send(json.dumps({"type": "ack", "envelope_id": env2_id}))
                passed("sent ack over WS")

        except Exception as e:
            failed(f"WebSocket failed: {e}")
            self.failures += 1

    async def _step_release_username(self, http: httpx.AsyncClient):
        step("10. Release @username (cleanup)")
        try:
            r = await http.delete(
                f"{self.relay_url}/api/v1/users/me/username",
                headers=self.auth_header,
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
