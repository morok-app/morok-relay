# Morok Relay API Reference

Version: 0.7.x (v0.8 package — DMS added)
Base URL: `https://relay1.morok.app`

All requests/responses are JSON unless noted. Hex values are lowercase.
Timestamps are epoch seconds (UTC, integer).

---

## Authentication

Morok uses Ed25519 challenge-response auth. No passwords, no email, no SMS.

### Flow

```
client                                 relay
  |   POST /api/v1/auth/challenge       |
  |   { pubkey_hex }                    |
  |  ----------------------------->     |
  |   { challenge_hex, expires_at }     |
  |  <-----------------------------     |
  |   (sign challenge locally)          |
  |   POST /api/v1/auth/verify          |
  |   { pubkey_hex, challenge_hex,      |
  |     timestamp, signature_hex }      |
  |  ----------------------------->     |
  |   { session_token, expires_at, ... }|
  |  <-----------------------------     |
```

### Signing

Canonical JSON of:
```json
{
  "morok_auth": "v1",
  "challenge": "<server hex>",
  "pubkey": "<your hex>",
  "timestamp": <epoch s>
}
```

Canonical = keys sorted ASCII, no whitespace, UTF-8, no NaN. Python:
`json.dumps(obj, sort_keys=True, separators=(",", ":"))`. Sign with Ed25519.

### Sessions

- TTL 7 days, sliding (renewed on each request)
- Header: `Authorization: Bearer <session_token>`
- **Side effect**: every authenticated request also bumps `last_check_in_at`
  on all of the caller's *armed* Dead Man's Switches. This is fire-and-forget,
  does not slow the response.
- Logout device: `DELETE /api/v1/auth/session`
- Panic: `POST /api/v1/auth/session/revoke-all`

---

## Endpoints

### Meta
- `GET /health` — `{ status, relay_name, version }`

### Auth
- `POST /api/v1/auth/challenge` → `{ challenge_hex, expires_at }`
- `POST /api/v1/auth/verify` → `{ session_token, expires_at, pubkey_hex }`
- `DELETE /api/v1/auth/session` → `{ revoked }`
- `POST /api/v1/auth/session/revoke-all` → `{ revoked }`

### Users
- `GET /api/v1/users/me` → MeInfo
- `POST /api/v1/users/me/username` body `{ username }` → MeInfo
  - tier minima: free 5+, premium 3+, admin 1+
- `DELETE /api/v1/users/me/username` → `{ released, cooldown_until }`
- `GET /api/v1/users/lookup/{username}` → UserInfo or 404

### 1-on-1 Messages
- `POST /api/v1/messages` → `{ envelope_id, queued, expires_at }`
- `GET /api/v1/messages?limit=50` → `{ envelopes, count }`
- `GET /api/v1/messages/{envelope_id}` → raw bytes
- `DELETE /api/v1/messages/{envelope_id}` → `{ acknowledged }`

### WebSocket
`WSS /ws/v1/inbox?token=<session_token>` — `catchup`, `new`, `ping`, `error`.
Client: `{"type":"ack","envelope_id":"..."}` / `{"type":"pong"}`.

---

## Groups and Channels

A group is a closed chat (≤50 free, ≤200 premium). A channel is a group
with `is_channel=true`: only admins post.

| Tier    | Max members | Custom slug |
|---------|-------------|-------------|
| Free    | 50          | No          |
| Premium | 200         | Yes         |
| Admin   | 200         | Yes         |

### Endpoints

- `POST /api/v1/groups` body `{ name_encrypted, is_channel, default_ttl_seconds, anonymous_senders, expires_at?, slug? }` → 201 GroupInfoDetailed
- `GET /api/v1/groups` → `[GroupInfo]`
- `GET /api/v1/groups/{group_id}` → GroupInfoDetailed (members only)
- `DELETE /api/v1/groups/{group_id}` → `{ deleted, group_id }` (creator only)
- `POST /api/v1/groups/{group_id}/members` body `{ pubkey_hex }` → GroupMembershipChange
- `DELETE /api/v1/groups/{group_id}/members/{pubkey_hex}` → GroupMembershipChange
- `GET /api/v1/groups/by-slug/{slug}` → GroupInfo (public, no member list)
- `POST /api/v1/groups/{group_id}/messages` → `{ envelope_id, queued, recipient_count, expires_at }`
  - `to` field in envelope = group UUID (not pubkey)
  - Relay fans out to all members (sender included for multi-device sync)

---

## Dead Man's Switch

**The "if I disappear, send this" mechanism.**

A user pre-arms a switch with:
- a **trigger period** (1 hour to 1 year of inactivity)
- a **pre-encrypted payload** (relay never sees plaintext)
- 1-N **trusted recipients** (their pubkeys)

The relay tracks `last_check_in_at`. Every authenticated request bumps it.
A separate hourly cron (the *DMS reaper*) finds any 'armed' switch where
`now - last_check_in_at > trigger_seconds` and **fires** it: delivers the
payload to each recipient as a regular envelope, then marks the switch
'triggered'.

### Tier limits

| Tier    | Max recipients per DMS |
|---------|------------------------|
| Free    | 5                      |
| Premium | 20                     |

No hard limit on number of switches per user. Users can have multiple
(one for family, one for work, etc).

### Privacy guarantees

- The relay **does not see the payload** — it's encrypted client-side
  with whatever key(s) the recipients hold.
- The relay **does see**: who created each DMS, who the recipients are,
  what the trigger period is, when last_check_in_at happens.
- The triggered envelope is **signed by the relay** (not by the creator)
  because the relay can't have the creator's private key. Clients see
  this through a `kind: "dms_trigger"` marker plus `dms_creator_pubkey`
  and `dms_id` fields in the envelope metadata. Clients should render
  this differently from a regular message — e.g. "Dead-man-switch from
  @creator (delivered via relay)".

### Trigger period bounds

- Minimum: **1 hour** (3600 seconds)
- Maximum: **1 year** (31536000 seconds)

Why 1 hour minimum: protects against accidentally arming a switch that
fires before you can check in. Why 1 year maximum: server resource limit;
also forces users to re-confirm intent annually.

### Endpoints

#### `POST /api/v1/dms`

Create a DMS. Returns 201 with the full DMSInfo including assigned `dms_id`.

```json
// Request
{
  "trigger_seconds": 86400,
  "payload_encrypted": "<base64 ciphertext, max 256 KB>",
  "recipient_pubkeys_hex": ["abc...", "def..."],
  "label": "family"            // optional, max 100 chars
}

// Response (201)
{
  "dms_id": "...",
  "trigger_seconds": 86400,
  "last_check_in_at": 1781000000,
  "fires_at": 1781086400,
  "label": "family",
  "status": "armed",
  "created_at": 1781000000,
  "triggered_at": null,
  "cancelled_at": null,
  "recipients": [
    { "recipient_pubkey_hex": "abc...", "delivered_at": null },
    ...
  ]
}
```

Errors:
- 400 `recipient_pubkey_not_64_hex_chars`
- 400 trigger_seconds below 1h or above 1y → Pydantic validation
- 400 `payload_encrypted_empty` / `payload_encrypted_too_large_max_262144_bytes`
- 400 `duplicate_recipient_pubkeys_not_allowed`
- 403 `too_many_recipients_for_tier_max_5` (or 20 for premium)

#### `GET /api/v1/dms`

List all of the caller's DMS (any status — armed, triggered, cancelled).

```json
[
  { "dms_id": "...", ... },
  ...
]
```

#### `GET /api/v1/dms/{dms_id}`

Get one DMS's full details. Only the owner can read.

Errors:
- 400 `malformed_dms_id`
- 404 `dms_not_found` (also returned when caller is not owner — no leak)

#### `POST /api/v1/dms/{dms_id}/check-in`

Explicit check-in. Sets `last_check_in_at = now`. Returns the new value
and the recomputed `fires_at`.

Note: any authenticated request from the owner also bumps check-in
automatically (fire-and-forget). This explicit endpoint exists so the
client can do a deliberate "I'm still here" with no other side effects,
and so users have a visible button to press.

Errors:
- 409 `dms_not_armed_status_triggered` / `dms_not_armed_status_cancelled`
- 404 `dms_not_found`

#### `DELETE /api/v1/dms/{dms_id}`

Cancel a DMS. Transitions 'armed' → 'cancelled' to prevent firing.
Idempotent (already-cancelled returns 200 with `cancelled: true`).
For 'triggered' (already fired), returns `cancelled: false` — can't
un-fire history.

```json
{ "dms_id": "...", "cancelled": true }
```

### DMS-triggered envelope shape

When the reaper fires a DMS, each recipient receives a regular envelope
in their inbox. Metadata (returned by `GET /messages`) contains:

```json
{
  "envelope_id": "...",
  "from": "<relay's pubkey hex>",   // NOT the creator
  "to": "<recipient pubkey hex>",
  "ts": 1781086400,
  "ttl": 86400,
  "sig": "<relay's signature>",
  "kind": "dms_trigger",
  "dms_creator_pubkey": "<creator hex>",
  "dms_id": "<original dms uuid>",
  "expires_at": 1781172800
}
```

Clients should:
1. Verify the signature against the **relay's** Ed25519 public key
   (known via DNS TXT records or federation handshake).
2. Recognize `kind: "dms_trigger"` and display the message distinctly
   ("Dead-man-switch from @<creator>" rather than "Message from @relay").
3. Decrypt the blob with whatever key the creator provisioned out-of-band
   (e.g. recipient's pubkey — the creator should have encrypted with X25519
   to each recipient's pubkey before storing).

### Cron schedule

- `morok-dms-reaper.timer`: runs hourly (`OnUnitActiveSec=1h`), first run
  10 minutes after boot.
- Idempotent: a 'triggered' switch is never re-fired. If the process
  crashes mid-fan-out, the DMS stays 'armed' until ALL recipients are
  delivered; on retry, recipients with `delivered_at != null` are skipped.

---

## Federation

Relay-to-relay endpoints. Regular clients should not call them.

- `POST /api/v1/federation/handshake`
- `POST /api/v1/federation/forward`
- `GET  /api/v1/federation/users/lookup/{username}`

---

## Error response shape

```json
{ "error": "snake_case_code", "detail": "optional human text" }
```

---

## TTL and message lifetime

- **Hard cap: 24 hours.** Reaper destroys blobs after this.
- **Reaper hourly. DMS reaper hourly. fstrim daily.**
- No server-side "burn after reading" — clients handle that.

---

## Privacy boundaries

What the relay knows: pubkey identities, optional usernames, group metadata,
DMS metadata (recipients, trigger time, payload size), envelope metadata.

What the relay does NOT know: message content, contact lists outside DMS
recipients, read state, group display names plaintext, DMS payload plaintext.

What's stored past TTL: nothing for messages. DMS rows stay (audit trail)
but their payloads are deleted after triggering or cancellation. fstrim
erases SSD blocks daily.
