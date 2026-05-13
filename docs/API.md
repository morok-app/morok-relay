# Morok Relay API Reference

Version: 0.5.x
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

After verify, include `Authorization: Bearer <session_token>` on
authenticated requests.

### Signing the challenge

The client signs a canonical JSON object:

```json
{
  "morok_auth": "v1",
  "challenge": "<challenge_hex from server>",
  "pubkey": "<your pubkey hex>",
  "timestamp": <current epoch seconds>
}
```

Canonical means: keys sorted ASCII, no whitespace, UTF-8, no NaN/Infinity.
In Python this is `json.dumps(obj, sort_keys=True, separators=(",", ":"))`.

Sign the resulting bytes with your Ed25519 private key → 64-byte signature.
Send as hex.

### Session tokens

- Lifetime: 7 days, sliding (extended on every authenticated request).
- Stored server-side in Redis. Revocable.
- Logout from this device: `DELETE /api/v1/auth/session`
- Logout from all devices (panic): `POST /api/v1/auth/session/revoke-all`

---

## Endpoints

### `GET /health`

Liveness check. No auth.

```bash
curl https://relay1.morok.app/health
```

```json
{ "status": "ok", "relay_name": "relay1.morok.app", "version": "0.5.0" }
```

### `POST /api/v1/auth/challenge`

Request a challenge to sign.

```json
// Request
{ "pubkey_hex": "9f2a...4f" }

// Response
{ "challenge_hex": "...", "expires_at": 1778600000 }
```

Challenge is one-time use, expires in 60 seconds.

### `POST /api/v1/auth/verify`

Submit signed challenge, receive session token.

```json
// Request
{
  "pubkey_hex": "9f2a...4f",
  "challenge_hex": "abcd...",
  "timestamp": 1778599999,
  "signature_hex": "...128 hex chars..."
}

// Response
{
  "session_token": "...64 hex chars...",
  "expires_at": 1779204999,
  "pubkey_hex": "9f2a...4f"
}
```

Errors:
- `401 challenge_not_found_or_expired`
- `401 pubkey_mismatch`
- `401 invalid_signature_or_stale_timestamp`

### `DELETE /api/v1/auth/session`

Revoke the current session token (this device only). Requires auth.

```json
{ "revoked": true }
```

### `POST /api/v1/auth/session/revoke-all`

Revoke ALL sessions for this pubkey (panic / lost device). Requires auth.

```json
{ "revoked": true }
```

### `GET /api/v1/users/me`

Profile of the authenticated user. First call lazily creates the row.

```json
{
  "pubkey_hex": "9f2a...4f",
  "username": "stas",       // or null
  "home_relay": "relay1.morok.app",
  "tier": "free",           // free | premium | admin
  "created_at": 1778600000
}
```

### `POST /api/v1/users/me/username`

Claim a username. Length minimum depends on your tier:

| Tier    | Min length |
|---------|------------|
| free    | 5 chars    |
| premium | 3 chars    |
| admin   | 1 char     |

Allowed chars: `a-z`, `0-9`, `_`. Must not start with digit or underscore.
Max 20 chars. Reserved names rejected (admin, root, system, morok, etc).

```json
// Request
{ "username": "stas" }

// Response (200) — full MeInfo
```

Errors:
- `400 invalid_username` — length, chars, reserved
- `409 username_taken`
- `409 username_in_cooldown` — released by another pubkey within 30 days

### `DELETE /api/v1/users/me/username`

Release current username. Enters 30-day cooldown — only the same pubkey
can re-claim within that window.

```json
{ "released": true, "cooldown_until": 1781192000 }
```

### `GET /api/v1/users/lookup/{username}`

Public lookup. No auth. Returns the pubkey + home_relay for a known username.

```json
{
  "pubkey_hex": "9f2a...4f",
  "username": "stas",
  "home_relay": "relay1.morok.app",
  "last_seen_at": 1778599000
}
```

Returns `404 username_not_found` if unclaimed.

### `POST /api/v1/messages`

Send an encrypted envelope. Auth required.

Envelope format — client signs the canonical JSON of all fields except `sig`:

```json
{
  "from":  "<sender_pubkey_hex>",     // must match your authenticated pubkey
  "to":    "<recipient_pubkey_hex>",
  "ts":    <current epoch seconds>,
  "ttl":   <seconds, 1 to 86400>,     // hard cap: 24h
  "blob":  "<base64 encrypted payload, max 256 KB>",
  "sig":   "<64-byte signature, hex>"
}
```

Response:

```json
{
  "envelope_id": "<sha256 of canonical envelope, hex>",
  "queued": true,
  "expires_at": 1778603600
}
```

If `queued: false` — this envelope (same envelope_id) was already submitted;
no error, just a no-op.

Errors:
- `400 envelope_invalid: ...` — signature/timestamp/format
- `400 blob_not_base64`
- `403 from_field_must_match_authenticated_pubkey`
- `413 blob_too_large_max_262144_bytes`

### `GET /api/v1/messages?limit=50`

List envelopes pending for the caller. Auth required. Returns oldest first.

```json
{
  "count": 2,
  "envelopes": [
    {
      "envelope_id": "...",
      "from": "...",
      "to": "...",
      "ts": 1778600000,
      "ttl": 3600,
      "sig": "...",
      "expires_at": 1778603600
    },
    ...
  ]
}
```

Does NOT include blob bytes — fetch each via `GET /messages/{id}`.
Does NOT mark as delivered — call `DELETE /messages/{id}` after processing.

### `GET /api/v1/messages/{envelope_id}`

Fetch the encrypted blob bytes. Auth required. Only the addressee can fetch.

Returns `application/octet-stream` — raw bytes, NOT JSON.

Errors:
- `400 malformed_envelope_id`
- `404 envelope_not_in_your_inbox` — wrong recipient or expired
- `404 blob_not_found` — already reaped

### `DELETE /api/v1/messages/{envelope_id}`

Acknowledge delivery. Removes envelope from your inbox queue. Idempotent.

```json
{ "acknowledged": true }
```

The blob is eventually secure-deleted from disk by the hourly reaper.

---

## WebSocket

### `WSS /ws/v1/inbox?token=<session_token>`

Real-time delivery. Send the session token as a query parameter (browsers
disallow custom headers on WS handshake).

#### Server → client frames

```json
// On connect — current inbox
{ "type": "catchup", "envelopes": [...], "count": N }

// When a new envelope arrives
{ "type": "new", "envelope": { ... metadata as in /messages list ... } }

// Every 30 seconds
{ "type": "ping" }

// On error
{ "type": "error", "detail": "..." }
```

#### Client → server frames

```json
// Acknowledge an envelope (equivalent to DELETE /messages/{id})
{ "type": "ack", "envelope_id": "..." }

// Heartbeat response
{ "type": "pong" }
```

After receiving a "new" frame, the client should fetch the blob via
`GET /messages/{envelope_id}` and then send an ack.

---

## Federation

These are relay-to-relay endpoints. Regular clients should not call them.

- `POST /api/v1/federation/handshake` — exchange identity with another relay
- `POST /api/v1/federation/forward`   — accept a forwarded envelope from peer
- `GET  /api/v1/federation/users/lookup/{username}` — public lookup, same as user-facing version

---

## Error response shape

All error responses (4xx/5xx) follow this shape:

```json
{ "error": "snake_case_error_code", "detail": "optional human-readable detail" }
```

The `error` field is stable — clients can switch on it. The `detail` is
informational only and may change between versions.

---

## TTL and message lifetime

- **Hard cap: 24 hours.** Regardless of client-requested TTL, the relay
  physically destroys blobs after 24 hours.
- **Default: 24 hours** (client may request less in the envelope's `ttl` field).
- **Reaper runs hourly** to secure-delete (overwrite + unlink) any blob whose
  TTL has expired or which has been acknowledged.
- **fstrim runs daily** to ensure SSD-level erasure of secure-deleted blocks.

There is no "burn after reading" feature on the server side. That is a
client-side responsibility: the client may delete the local copy any time
after reading, but the server already has its own short TTL working.

---

## Privacy guarantees

What the relay knows:
- Your public key (= identity)
- Your optional @username (if you claimed one)
- The fact that an envelope exists, sender pubkey, recipient pubkey, timestamp, size
- The encrypted blob itself (cannot decrypt)

What the relay does NOT know:
- Message content (encrypted with X25519 + XSalsa20-Poly1305 client-side)
- Your contact list (lives only in your client)
- When you read a message (no read receipts on server side)
- Your IP address beyond nginx's 24-hour rotating access log

What the relay never stores past TTL:
- Any blob older than 24 hours
- Any blob whose recipient ACK'd delivery (cleaned within ~1 hour by reaper)
