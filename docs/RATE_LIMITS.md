# Rate Limits

Configured limits as of v0.8. All values configurable in `.env`:

| Endpoint | Bucket | Limit | Identifier |
|---|---|---|---|
| `POST /api/v1/auth/challenge` | `auth_challenge` | 10/min | IP |
| `POST /api/v1/auth/verify` | `auth_verify` | 10/min | IP |
| `POST /api/v1/messages` | `messages_send` | 60/min | pubkey |
| `POST /api/v1/groups` | `groups_create` | 5/min | pubkey |
| `POST /api/v1/groups/{id}/messages` | `groups_message` | 30/min | pubkey |
| `POST /api/v1/dms` | `dms_create` | 5/min | pubkey |
| WebSocket inbox concurrent | n/a | 5 active | pubkey |

Not rate-limited:
- `GET` endpoints (read-only)
- `DELETE` endpoints (single row updates)
- `POST /auth/session/revoke-all` (auth required, panic action)
- `POST /dms/{id}/check-in` (trivial single-row update)
- All federation endpoints (relay-to-relay, not yet enabled)

## On exceeded limit

Response: `429 Too Many Requests`
```
HTTP/1.1 429 Too Many Requests
Retry-After: 47
Content-Type: application/json

{"error": "rate_limited_auth_challenge_11_of_10_per_minute"}
```

Client should wait `Retry-After` seconds and retry.

## Disable for tests

In `.env`:
```
MOROK_RATE_LIMIT_ENABLED=false
```

This disables ALL rate limiting. Useful for running `client_simulator.py`
without hitting limits when iterating.

## Tune in `.env`

```
MOROK_RATE_LIMIT_AUTH_PER_MINUTE=10
MOROK_RATE_LIMIT_MESSAGES_PER_MINUTE=60
MOROK_RATE_LIMIT_GROUP_CREATE_PER_MINUTE=5
MOROK_RATE_LIMIT_GROUP_MESSAGES_PER_MINUTE=30
MOROK_RATE_LIMIT_DMS_CREATE_PER_MINUTE=5
MOROK_RATE_LIMIT_WS_CONNECTIONS_PER_PUBKEY=5
```

Changes require `systemctl restart morok-relay`.

## Implementation

Fixed-window counter in Redis. Key shape:
```
morok:ratelimit:{bucket}:{identifier}:{minute_epoch//60}
```

INCR + EXPIRE 90s (slightly longer than the 60s window to outlive boundary).
If count > limit at check time → 429 with Retry-After. Failure mode is
**fail-open**: if Redis is unreachable, requests pass through. Rationale:
rate limiting is defense-in-depth, not authentication. Failing closed
would DoS ourselves whenever Redis blips.

## Future improvements (post-v0.8)

- **Sliding window** instead of fixed-window (more fair near boundaries)
- **Per-tier limits**: premium gets 2-5× free limits
- **Adaptive limits**: tighter if relay is overloaded, looser if idle
- **IP allowlist / blocklist**: explicit blocks for known abusers
- **Per-bucket Retry-After fine-tuning**: e.g. exponential backoff for repeat offenders
