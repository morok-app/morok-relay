# Morok Relay API Reference

Version: 0.6.x
Base URL: `https://relay1.morok.app`

All requests/responses are JSON unless noted. All hex values are lowercase.
Timestamps are epoch seconds (UTC, integer).

---

## Authentication

Morok uses Ed25519 challenge-response auth. No passwords, no email, no SMS.
The client holds a 32-byte Ed25519 private key; the server only ever sees
the corresponding public key and signed challenges.

### Flow

```
client                                 relay
  |                                      |
  |  POST /api/v1/auth/challenge        |
  |  { pubkey_hex }                     |
  |  ----------------------------->     |
  |                                      |
  |  { challenge_hex, expires_at }      |
  |  <-----------------------------     |
  |                                      |
  |  (sign challenge locally)           |
  |                                      |
  |  POST /api/v1/auth/verify           |
  |  { pubkey_hex, challenge_hex,       |
  |    timestamp, signature_hex }       |
  |  ----------------------------->     |
  |                                      |
  |  { session_token, expires_at, ... } |
  |  <-----------------------------     |
```

### Signing the challenge

The client signs canonical JSON of:

```json
{
  "morok_auth": "v1",
  "challenge": "<challenge_hex from server>",
  "pubkey": "<your pubkey hex>",
  "timestamp": <current epoch seconds>
}
```

Canonical: keys sorted ASCII, no whitespace, UTF-8, no NaN. In Python this
is `json.dumps(obj, sort_keys=True, separators=(",", ":"))`.

Sign the bytes with your Ed25519 private key → 64-byte signature. Send as hex.

### Session tokens

- Lifetime: 7 days, sliding.
- Header: `Authorization: Bearer <session_token>`
- Logout this device: `DELETE /api/v1/auth/session`
- Panic logout: `POST /api/v1/auth/session/revoke-all`

---

## Endpoints

### `GET /health`
No auth.

```json
{ "status": "ok", "relay_name": "relay1.morok.app", "version": "0.6.0" }
```

### `POST /api/v1/auth/challenge`
```json
// Request
{ "pubkey_hex": "9f2a...4f" }
// Response
{ "challenge_hex": "...", "expires_at": 1778600000 }
```

### `POST /api/v1/auth/verify`
```json
// Request
{
  "pubkey_hex": "...",
  "challenge_hex": "...",
  "timestamp": 1778599999,
  "signature_hex": "..."
}
// Response
{ "session_token": "...", "expires_at": 1779204999, "pubkey_hex": "..." }
```

### `DELETE /api/v1/auth/session` — revoke current token
### `POST /api/v1/auth/session/revoke-all` — panic

### `GET /api/v1/users/me`
Returns the authenticated user. First call creates the row.

```json
{
  "pubkey_hex": "...",
  "username": "stas" | null,
  "home_relay": "relay1.morok.app",
  "tier": "free" | "premium" | "admin",
  "created_at": 1778600000
}
```

### `POST /api/v1/users/me/username`
Tier minima: free 5+, premium 3+, admin 1+. Allowed chars: `a-z 0-9 _`.
Cannot start with digit or underscore. Reserved names rejected.

Errors: 400 `invalid_username`, 409 `username_taken`, 409 `username_in_cooldown`.

### `DELETE /api/v1/users/me/username`
30-day cooldown. Only the original pubkey can re-claim within the window.

### `GET /api/v1/users/lookup/{username}` — public
Returns `404 username_not_found` if unclaimed.

### `POST /api/v1/messages` — submit envelope
Envelope fields signed (all fields except `sig` go into canonical JSON):
- `from`, `to`: 64-hex pubkey
- `ts`: epoch seconds
- `ttl`: 1 to 86400 (24h hard cap)
- `blob`: base64 encrypted, max 256 KB
- `sig`: 128-hex Ed25519 signature

### `GET /api/v1/messages?limit=50` — list pending
### `GET /api/v1/messages/{envelope_id}` — fetch blob bytes
### `DELETE /api/v1/messages/{envelope_id}` — ack delivery

### `WSS /ws/v1/inbox?token=<session_token>` — real-time delivery
See server frames: `catchup`, `new`, `ping`, `error`.
Client → server: `{"type":"ack","envelope_id":"..."}`, `{"type":"pong"}`.

---

## Groups and Channels

A group is a closed chat (up to 50/200 members). A channel is a group with
`is_channel=true`: only admins can post, but membership has no public cap
(other than tier limits enforced at creation).

In v1, the **creator is the sole admin**. Adding admins / transferring
ownership comes later.

### Tier limits

| Tier    | Max members | Custom slug |
|---------|-------------|-------------|
| Free    | 50          | No          |
| Premium | 200         | Yes         |
| Admin   | 200         | Yes         |

`max_members` is set on the group at creation time. If the creator later
upgrades, existing groups keep their original cap; new groups get the
upgraded cap.

### Encryption

Members share a `sender-key` distributed client-side. The relay never sees
the plaintext name, message content, or sender-key. Group display names are
sent encrypted (`name_encrypted` field, base64-encoded ciphertext).

### Anonymous senders — privacy boundary

A group can be created with `anonymous_senders: true`. In that mode, clients
SHOULD render messages as "from the group itself" rather than from a specific
member.

**Important limitation in v1:** this is anonymity *toward other members*, not
*toward the relay*. The relay still observes which member sent the message
(it has to, to verify the signature). True sender-anonymity against the relay
requires ring signatures over group membership and is on the v2 roadmap.

Document this clearly to users — don't mis-sell anonymity that doesn't exist
yet.

### Expiry

A group with `expires_at` set will be deleted (and all its messages purged)
after that epoch second. Powers "chats with a predetermined end". Useful
for protests, single-event coordination, time-bounded operations.

Note: the per-message 24h hard cap still applies. `expires_at` is for the
GROUP itself; messages within it still vanish individually after their TTL.

### `POST /api/v1/groups`

Create a group or channel. Caller becomes the sole admin.

```json
// Request
{
  "name_encrypted": "<base64 of encrypted name, max 2 KB decoded>",
  "is_channel": false,
  "default_ttl_seconds": 86400,
  "anonymous_senders": false,
  "expires_at": 1810000000,    // optional, must be < 1 year out
  "slug": "myteam"             // optional, premium only
}
```

Returns 201 with the full group (including the creator as the only member).

Errors:
- `400 invalid_slug` — Pydantic-level validation
- `400 expires_at_must_be_in_future`
- `400 expires_at_too_far_in_future` — capped at 1 year
- `403 slug_requires_premium`
- `409 slug_taken`

### `GET /api/v1/groups`

List groups where the caller is a member. Ordered newest first.

```json
[
  {
    "group_id": "...",
    "creator_pubkey_hex": "...",
    "name_encrypted": "<base64>",
    "is_channel": false,
    "default_ttl_seconds": 86400,
    "anonymous_senders": false,
    "expires_at": null,
    "slug": null,
    "max_members": 50,
    "created_at": 1778600000,
    "member_count": 3
  }
]
```

### `GET /api/v1/groups/{group_id}`

Full info including member list. Only members can read.

Adds:
```json
{
  ...
  "members": [
    { "pubkey_hex": "...", "is_admin": true, "joined_at": 1778600000 },
    ...
  ]
}
```

Errors:
- `400 malformed_group_id`
- `403 not_a_member`
- `404 group_not_found`

### `DELETE /api/v1/groups/{group_id}`

Soft-delete the group. Only the creator can call this. Returns 204.
Reaper purges associated messages and physically deletes the row within 24h.

Errors: `403 only_creator_can_delete`, `404 group_not_found`.

### `POST /api/v1/groups/{group_id}/members`

Admin adds a member by pubkey. Idempotent: adding an existing member returns
200 with current member_count.

```json
// Request
{ "pubkey_hex": "..." }
// Response
{
  "group_id": "...",
  "member_pubkey_hex": "...",
  "action": "added",
  "member_count": 4
}
```

Errors:
- `403 only_admin_can_add_members`
- `409 group_full_max_50_members` (or 200 for premium)

### `DELETE /api/v1/groups/{group_id}/members/{pubkey_hex}`

Two modes:
1. Self-leave: caller pubkey == target → user leaves.
2. Admin kick: caller is admin → removes the target.

The creator cannot leave or be removed via this endpoint. They must
`DELETE /api/v1/groups/{id}` instead.

Errors:
- `403 must_be_self_or_admin`
- `404 not_a_member`
- `409 creator_cannot_leave_must_delete_group`

### `GET /api/v1/groups/by-slug/{slug}`

Public lookup of a channel by its slug — no auth, no member list returned.

Returns the same `GroupInfo` shape as GET /groups (without members).

Errors: `404 slug_not_found`.

### Group messaging

`POST /api/v1/groups/{group_id}/messages` is NOT implemented in v0.6 — it
ships in v0.7 (next sub-session). When live, it will accept a single envelope
addressed to the group_id and fan-out to all members' inboxes via the same
Redis queue / WebSocket pipeline used for 1-on-1 messages.

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

The `error` field is stable — clients can switch on it.

---

## TTL and message lifetime

- **Hard cap: 24 hours.** Server destroys any blob after 24h regardless of
  client-requested TTL.
- **Default: 24 hours.** Client may request less.
- Reaper runs hourly; fstrim runs daily to erase deleted SSD blocks.
- No "burn after reading" on the server side — that's a client-side concern.

---

## Privacy boundaries

What the relay knows: pubkey identities, optional usernames, group metadata
(member list, encrypted names, settings), envelope metadata (from, to, ts,
size).

What the relay does NOT know: message content, contact lists, read state,
sender-keys, group names in plaintext.

What's stored past TTL: nothing. Blobs older than 24h are reaped.
