"""
Morok end-to-end test client.

Steps (v0.8):
    1.  GET /health
    2.  Auth (challenge + verify)
    3.  GET /me
    4.  Claim @username
    5.  Send envelope to SELF
    6.  List inbox
    7.  Fetch blob
    8.  ACK envelope
    9.  WebSocket inbox

   Group flow:
   10.  Bob logs in
   11.  Alice creates a group
   12.  Alice adds Bob
   13.  Alice posts a group message
   14.  Bob receives and fetches
   15.  Alice deletes the group

   DMS flow (v0.8):
   16.  Alice creates a DMS (trigger=1h, recipient=Bob)
   17.  Alice lists her DMS — sees the one she just made
   18.  Alice check-in extends trigger
   19.  Alice cancels the DMS

   20.  Release @username (cleanup)

Usage:
    python tools/client_simulator.py [--relay https://relay1.morok.app]
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


def build_envelope_to_pubkey(sender_sk, recipient_pubkey, blob, ttl_seconds=3600):
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


def build_group_envelope(sender_sk, group_id, blob, ttl_seconds=3600):
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


OK = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
INFO = "\033[94mi\033[0m"


def step(label): print(f"\n{INFO} {label}")
def passed(msg): print(f"  {OK} {msg}")
def failed(msg): print(f"  {FAIL} {msg}")


class Identity:
    def __init__(self, label):
        self.label = label
        self.sk = nacl.signing.SigningKey.generate()
        self.pubkey = bytes(self.sk.verify_key)
        self.session_token = None

    @property
    def short_pubkey(self): return self.pubkey.hex()[:16]

    @property
    def auth_header(self):
        if not self.session_token:
            return {}
        return {"Authorization": f"Bearer {self.session_token}"}


async def login(http, relay_url, identity):
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


class TestClient:
    def __init__(self, relay_url):
        self.relay_url = relay_url.rstrip("/")
        self.ws_url = (
            self.relay_url
            .replace("https://", "wss://")
            .replace("http://", "ws://")
        )
        self.alice = Identity("alice")
        self.bob = Identity("bob")
        self.username = None
        self.failures = 0

    async def run(self):
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

            # DMS flow (v0.8)
            dms_id = await self._step_create_dms(http)
            if dms_id:
                await self._step_list_my_dms(http, dms_id)
                await self._step_check_in_dms(http, dms_id)
                await self._step_cancel_dms(http, dms_id)

            await self._step_release_username(http)

        print()
        if self.failures == 0:
            print(f"{OK} All steps passed.")
            return 0
        print(f"{FAIL} {self.failures} step(s) failed.")
        return 1

    # ----- 1-on-1 -----

    async def _step_health(self, http):
        step("1. GET /health")
        try:
            r = await http.get(f"{self.relay_url}/health")
            r.raise_for_status()
            d = r.json()
            assert d["status"] == "ok"
            passed(f"version={d['version']}, relay={d['relay_name']}")
        except Exception as e:
            failed(f"health failed: {e}")
            self.failures += 1

    async def _step_auth(self, http):
        step("2. Auth — alice")
        if await login(http, self.relay_url, self.alice):
            passed(f"session: {self.alice.session_token[:16]}...")
        else:
            self.failures += 1

    async def _step_get_me(self, http):
        step("3. GET /me")
        try:
            r = await http.get(
                f"{self.relay_url}/api/v1/users/me",
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            d = r.json()
            assert d["tier"] == "free"
            passed(f"tier={d['tier']}, no username yet")
        except Exception as e:
            failed(f"/me failed: {e}")
            self.failures += 1

    async def _step_claim_username(self, http):
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
            passed(f"claimed @{self.username}")
        except Exception as e:
            failed(f"claim failed: {e}")
            self.failures += 1

    async def _step_send_envelope_to_self(self, http):
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
            self.envelope_id = r.json()["envelope_id"]
            passed(f"queued: {self.envelope_id[:16]}...")
        except Exception as e:
            failed(f"send failed: {e}")
            self.failures += 1
            self.envelope_id = None

    async def _step_list_inbox(self, http):
        step("6. List inbox")
        try:
            r = await http.get(
                f"{self.relay_url}/api/v1/messages",
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            d = r.json()
            found = any(
                e["envelope_id"] == getattr(self, "envelope_id", None)
                for e in d["envelopes"]
            )
            if found:
                passed(f"found ({d['count']} total)")
            else:
                failed(f"not in inbox ({d['count']} others)")
                self.failures += 1
        except Exception as e:
            failed(f"list failed: {e}")
            self.failures += 1

    async def _step_fetch_blob(self, http):
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
                passed(f"bytes match ({len(r.content)})")
                return self.envelope_id
            failed("blob mismatch")
            self.failures += 1
            return None
        except Exception as e:
            failed(f"fetch failed: {e}")
            self.failures += 1
            return None

    async def _step_ack(self, http, envelope_id):
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

    async def _step_websocket(self, http):
        step("9. WebSocket inbox")
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

                payload2 = b"ws-push " + secrets.token_bytes(8)
                env2 = build_envelope_to_pubkey(
                    self.alice.sk, self.alice.pubkey, payload2, 600
                )
                r = await http.post(
                    f"{self.relay_url}/api/v1/messages",
                    json=env2, headers=self.alice.auth_header,
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
                    except TimeoutError:
                        continue

                if got_new:
                    passed("real-time push received")
                else:
                    failed("no push within 5s")
                    self.failures += 1
                await ws.send(json.dumps({"type": "ack", "envelope_id": env2_id}))
                passed("ack sent")
        except Exception as e:
            failed(f"WS failed: {e}")
            self.failures += 1

    # ----- Group -----

    async def _step_login_bob(self, http):
        step("10. Bob logs in")
        if not await login(http, self.relay_url, self.bob):
            self.failures += 1
            return
        passed(f"bob session: {self.bob.session_token[:16]}...")
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

    async def _step_create_group(self, http):
        step("11. Alice creates a group")
        fake_name = b"\x00\x01\x02\x03" + secrets.token_bytes(64)
        try:
            r = await http.post(
                f"{self.relay_url}/api/v1/groups",
                json={
                    "name_encrypted": base64.b64encode(fake_name).decode(),
                    "is_channel": False,
                    "default_ttl_seconds": 3600,
                    "anonymous_senders": False,
                },
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            d = r.json()
            assert d["max_members"] == 50
            passed(f"group_id={d['group_id'][:8]}...")
            return d["group_id"]
        except Exception as e:
            failed(f"create group failed: {e}")
            self.failures += 1
            return None

    async def _step_add_member(self, http, group_id):
        step("12. Alice adds Bob")
        try:
            r = await http.post(
                f"{self.relay_url}/api/v1/groups/{group_id}/members",
                json={"pubkey_hex": self.bob.pubkey.hex()},
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            assert r.json()["member_count"] == 2
            passed("Bob added")
        except Exception as e:
            failed(f"add failed: {e}")
            self.failures += 1

    async def _step_send_group_message(self, http, group_id):
        step("13. Alice posts to group")
        self.group_payload = b"group hi " + secrets.token_bytes(16)
        env = build_group_envelope(self.alice.sk, group_id, self.group_payload, 3600)
        try:
            r = await http.post(
                f"{self.relay_url}/api/v1/groups/{group_id}/messages",
                json=env, headers=self.alice.auth_header,
            )
            r.raise_for_status()
            d = r.json()
            assert d["recipient_count"] == 2
            passed(f"fan-out to {d['recipient_count']}")
            return d["envelope_id"]
        except Exception as e:
            failed(f"group send failed: {e}")
            self.failures += 1
            return None

    async def _step_bob_receives_group(self, http, envelope_id):
        step("14. Bob fetches the group message")
        try:
            r = await http.get(
                f"{self.relay_url}/api/v1/messages",
                headers=self.bob.auth_header,
            )
            r.raise_for_status()
            found = next(
                (e for e in r.json()["envelopes"] if e["envelope_id"] == envelope_id),
                None,
            )
            if not found or not found.get("group_id"):
                failed("group msg not in Bob's inbox")
                self.failures += 1
                return
            passed(f"in inbox (group_id={found['group_id'][:8]}...)")
        except Exception as e:
            failed(f"bob list failed: {e}")
            self.failures += 1
            return

        try:
            r = await http.get(
                f"{self.relay_url}/api/v1/messages/{envelope_id}",
                headers=self.bob.auth_header,
            )
            r.raise_for_status()
            if r.content == self.group_payload:
                passed(f"bytes match ({len(r.content)})")
            else:
                failed("blob mismatch")
                self.failures += 1
        except Exception as e:
            failed(f"bob fetch failed: {e}")
            self.failures += 1

    async def _step_delete_group(self, http, group_id):
        step("15. Alice deletes the group")
        try:
            r = await http.delete(
                f"{self.relay_url}/api/v1/groups/{group_id}",
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            assert r.json()["deleted"] is True
            passed("group deleted")
        except Exception as e:
            failed(f"delete failed: {e}")
            self.failures += 1

    # ----- DMS (v0.8) -----

    async def _step_create_dms(self, http):
        step("16. Alice creates a DMS")
        fake_payload = b"\x00\x01" + secrets.token_bytes(128)
        try:
            r = await http.post(
                f"{self.relay_url}/api/v1/dms",
                json={
                    "trigger_seconds": 3600,
                    "payload_encrypted": base64.b64encode(fake_payload).decode(),
                    "recipient_pubkeys_hex": [self.bob.pubkey.hex()],
                    "label": "test-dms",
                },
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            d = r.json()
            assert d["status"] == "armed"
            assert len(d["recipients"]) == 1
            assert d["recipients"][0]["recipient_pubkey_hex"] == self.bob.pubkey.hex()
            passed(f"dms_id={d['dms_id'][:8]}..., armed, fires_at in {d['fires_at']-int(time.time())}s")
            return d["dms_id"]
        except Exception as e:
            failed(f"create DMS failed: {e}")
            if isinstance(e, httpx.HTTPStatusError):
                failed(f"  response: {e.response.text}")
            self.failures += 1
            return None

    async def _step_list_my_dms(self, http, expected_dms_id):
        step("17. Alice lists her DMS")
        try:
            r = await http.get(
                f"{self.relay_url}/api/v1/dms",
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            items = r.json()
            found = any(d["dms_id"] == expected_dms_id for d in items)
            if found:
                passed(f"sees {len(items)} DMS including ours")
            else:
                failed(f"our DMS not in list ({len(items)} others)")
                self.failures += 1
        except Exception as e:
            failed(f"list DMS failed: {e}")
            self.failures += 1

    async def _step_check_in_dms(self, http, dms_id):
        step("18. Alice explicit check-in")
        try:
            r = await http.post(
                f"{self.relay_url}/api/v1/dms/{dms_id}/check-in",
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            d = r.json()
            now = int(time.time())
            # last_check_in_at should be ~now
            assert abs(d["last_check_in_at"] - now) < 10
            assert d["fires_at"] > now
            passed(f"check-in bumped, fires_at = now+{d['fires_at']-now}s")
        except Exception as e:
            failed(f"check-in failed: {e}")
            self.failures += 1

    async def _step_cancel_dms(self, http, dms_id):
        step("19. Alice cancels the DMS")
        try:
            r = await http.delete(
                f"{self.relay_url}/api/v1/dms/{dms_id}",
                headers=self.alice.auth_header,
            )
            r.raise_for_status()
            d = r.json()
            assert d["cancelled"] is True
            passed("DMS cancelled")
        except Exception as e:
            failed(f"cancel failed: {e}")
            self.failures += 1

    async def _step_release_username(self, http):
        step("20. Release @username (cleanup)")
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


async def main():
    p = argparse.ArgumentParser()
    p.add_argument("--relay", default=DEFAULT_RELAY)
    args = p.parse_args()
    return await TestClient(args.relay).run()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
