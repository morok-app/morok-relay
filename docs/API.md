# Morok Relay API Reference

Version: 0.7.x
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

- `GET /api/v1/users/me` → MeInfo (creates row on first call)
- `POST /api/v1/users/me/username` body `{ username }` → MeInfo
  - tier minima: free 5+, premium 3+, admin 1+
  - chars: `a-z 0-9 _`, no leading digit/underscore, max 20
  - errors: 400 `invalid_username`, 409 `username_taken`, 409 `username_in_cooldown`
- `DELETE /api/v1/users/me/username` → `{ released, cooldown_until }` (30-day cooldown)
- `GET /api/v1/users/lookup/{username}` → UserInfo or 404 (public)

### 1-on-1 Messages

Envelope is signed: canonical JSON of all fields except `sig`, then Ed25519.

```json
{
  "from": "<sender pubkey hex>",
  "to":   "<recipient pubkey hex>",
  "ts":   <epoch s>,
  "ttl":  <1 to 86400, 24h hard cap>,
  "blob": "<base64 encrypted, max 256 KB>",
  "sig":  "<128 hex>"
}
```

- `POST /api/v1/messages` → `{ envelope_id, queued, expires_at }`
- `GET /api/v1/messages?limit=50` → `{ envelopes, count }`
- `GET /api/v1/messages/{envelope_id}` → raw bytes (`application/octet-stream`)
- `DELETE /api/v1/messages/{envelope_id}` → `{ acknowledged }`

### WebSocket

`WSS /ws/v1/inbox?token=<session_token>`

Server frames:
- `{"type":"catchup","envelopes":[...],"count":N}` on connect
- `{"type":"new","envelope":{...}}` per new envelope
- `{"type":"ping"}` every 30s
- `{"type":"error","detail":"..."}`

Client frames:
- `{"type":"ack","envelope_id":"..."}` (= DELETE /messages/{id})
- `{"type":"pong"}`

---

## Groups and Channels

A group is a closed chat (≤50 free, ≤200 premium). A channel is a group
with `is_channel=true`: only admins post, no special read cap.

### Tier limits

| Tier    | Max members | Custom slug |
|---------|-------------|-------------|
| Free    | 50          | No          |
| Premium | 200         | Yes         |
| Admin   | 200         | Yes         |

`max_members` is fixed at creation. Future tier upgrades don't change
existing groups.

### Encryption model

Members share a sender-key, distributed client-side. The relay never sees
plaintext, sender-keys, or display names (which travel as `name_encrypted`
base64 ciphertext).

### Anonymous senders

If `anonymous_senders=true`, clients SHOULD render messages as from the
group itself. The relay still observes who sent each message (it must, to
verify signatures) — this is anonymity *toward other members*, not
*toward the relay*. v2 will add ring signatures for the latter.

### Expiry

`expires_at` is the epoch second after which the whole group (and all its
messages) is destroyed. Per-message 24h hard cap still applies inside.
Useful for protests, single-event coordination, time-bounded operations.

### Endpoints

- `POST /api/v1/groups` body:
  ```json
  {
    "name_encrypted": "<base64, max 2KB decoded>",
    "is_channel": false,
    "default_ttl_seconds": 86400,
    "anonymous_senders": false,
    "expires_at": 1810000000,   // optional, <1 year out
    "slug": "myteam"            // premium only
  }
  ```
  → 201 GroupInfoDetailed (caller is sole admin)
  - 400 `invalid_slug`, `expires_at_must_be_in_future`, `expires_at_too_far_in_future`
  - 403 `slug_requires_premium`
  - 409 `slug_taken`

- `GET /api/v1/groups` → `[GroupInfo]` (groups I'm in, newest first)

- `GET /api/v1/groups/{group_id}` → GroupInfoDetailed (members only)
  - 400 `malformed_group_id`, 403 `not_a_member`, 404 `group_not_found`

- `DELETE /api/v1/groups/{group_id}` → `{ deleted, group_id }` (creator only)
  - Reaper purges associated messages and physically deletes the row within 24h.
  - Returns 200 with body (not 204 because FastAPI rejects body+204).

- `POST /api/v1/groups/{group_id}/members` body `{ pubkey_hex }` → GroupMembershipChange
  - Admin adds. Idempotent.
  - 403 `only_admin_can_add_members`, 409 `group_full_max_N_members`

- `DELETE /api/v1/groups/{group_id}/members/{pubkey_hex}` → GroupMembershipChange
  - Self-leave OR admin kicks.
  - 403 `must_be_self_or_admin`, 404 `not_a_member`,
    409 `creator_cannot_leave_must_delete_group`

- `GET /api/v1/groups/by-slug/{slug}` → GroupInfo (no auth, no member list)
  - 404 `slug_not_found`

### Group messaging

Group envelope is structurally similar to 1-on-1, but `to` is the **group
UUID** (36 chars including hyphens), not a pubkey:

```json
{
  "from": "<sender pubkey hex>",
  "to":   "<group UUID>",
  "ts":   <epoch s>,
  "ttl":  <1 to 86400>,
  "blob": "<base64 encrypted, max 256 KB>",
  "sig":  "<128 hex>"
}
```

- `POST /api/v1/groups/{group_id}/messages` → `{ envelope_id, queued, recipient_count, expires_at }`

Server validates:
- URL `group_id` matches envelope `to`
- `from` matches authenticated session
- Caller is a member
- If channel: caller is the admin
- Signature valid over canonical envelope (sans `sig`)
- Timestamp within window (-5min … +1min)
- Blob ≤ 256 KB

On success:
- Blob written ONCE to disk
- Fan-out: queued in every member's inbox (including sender — for multi-
  device sync)
- Real-time pushed via WebSocket to anyone with an active connection

Recipients see the message in `GET /api/v1/messages` with metadata showing
`group_id` set (so clients can route it to the group thread rather than
to a 1-on-1 conversation).

Errors:
- 400 `envelope_to_must_match_url_group_id`, `signature_invalid`, `envelope_too_old`, `envelope_from_the_future`, `blob_not_base64`
- 403 `from_field_must_match_authenticated_pubkey`, `not_a_member`, `channel_admin_only_post`
- 413 `blob_too_large_max_262144_bytes`

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

`error` is stable; `detail` may change.

---

## TTL and message lifetime

- **Hard cap: 24 hours.** Reaper destroys any blob older than this.
- **Default: 24 hours.** Clients may request less per message.
- **Reaper hourly.** **fstrim daily.**
- No server-side "burn after reading" — clients handle that locally.

---

## Privacy boundaries

What the relay knows: pubkey identities, optional usernames, group metadata
(membership, encrypted names, settings), envelope metadata (from, to, ts,
size).

What the relay does NOT know: message content, contact lists, read state,
sender-keys, group display names in plaintext.

What's stored past TTL: nothing. Blobs older than 24h are reaped, fstrim
erases the underlying SSD blocks daily.
