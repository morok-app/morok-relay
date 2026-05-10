# morok-relay

Federated relay server for the [Morok messenger](https://morok.app).

**Status:** v0.1, in active development. Not for production use.

## What this does

A relay server is the part of Morok that lives on the internet. Clients
connect to it to send and receive encrypted messages. Multiple relays
federate with each other so users on different relays can talk.

The relay never sees plaintext, never has user private keys, and stores
the absolute minimum needed for delivery. Encrypted message blobs are
held briefly in a delivery queue and physically destroyed after delivery
or 48 hours, whichever comes first.

This is just the relay. The Android client is a separate repository.

## Stack

- Python 3.12+
- FastAPI (async)
- PostgreSQL 16+ (metadata)
- Redis 7+ (message queue, challenges, rate limits)
- PyNaCl (libsodium bindings)

## Local setup

Requires Python 3.12+, PostgreSQL, Redis.

```bash
# 1. Clone and enter
git clone git@github.com:morok-app/morok-relay.git
cd morok-relay

# 2. Virtual environment
python3.12 -m venv .venv
source .venv/bin/activate

# 3. Dependencies
pip install -r requirements.txt

# 4. Config
cp .env.example .env
# Edit .env: at minimum set MOROK_DB_DSN to point at your local Postgres.

# 5. Generate this relay's keypair (federation identity)
python -m morok_relay.scripts.generate_relay_keypair
# Copy the two lines into .env

# 6. Database
createdb morok_relay
# Migrations will be added in a later commit; for now the DB starts empty.

# 7. Redis
# Make sure redis-server is running locally (default port 6379).

# 8. Run
uvicorn morok_relay.main:app --reload
```

Server starts on `http://localhost:8000`. Try:

```bash
curl http://localhost:8000/health
# {"status":"ok","relay_name":"...","version":"0.1.0"}
```

In dev mode, OpenAPI docs are at `http://localhost:8000/docs`.

## Tests

```bash
pytest -v
```

Crypto tests live in `tests/test_crypto.py` and are the most critical —
if they fail, the server is broken.

## Project layout

```
morok-relay/
  morok_relay/
    __init__.py
    main.py           # FastAPI app entry point
    config.py         # Settings (Pydantic)
    db.py             # DB and Redis connection management
    models.py         # SQLAlchemy ORM models
    schemas.py        # Pydantic request/response schemas
    crypto.py         # Ed25519, X25519, envelope verification
    scripts/          # CLI utilities (keygen, etc.)
  tests/
    test_crypto.py    # crypto verification tests
  requirements.txt
  .env.example
  README.md
```

## What's NOT here yet (coming in next commits)

- Auth endpoints (challenge / verify)
- Username registration
- Message envelope intake
- Delivery queue (Redis)
- Blob storage with secure delete
- WebSocket connection for clients
- Federation API (relay-to-relay)
- Group / channel endpoints
- Database migrations (Alembic)
- nginx / systemd deploy configs

Each of these is a separate, focused commit on top of the foundation here.

## Security model

See `docs/THREAT_MODEL.md` (TODO) and the main project's [product brief].

Short version:
- **Threat we mitigate:** plaintext exposure (server-side or in transit),
  metadata retention, push-notification leakage, MITM at first contact.
- **Threat we don't yet mitigate:** traffic analysis (cover traffic is v2),
  endpoint compromise (out of scope for any messenger), social engineering.

If you find a security issue, email `morok.messenger@pm.me`. Do not file a
public issue.

## License

TBD. Likely AGPL-3.0 once we open-source. Currently private.
