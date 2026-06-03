-- Login audit log — one row per successful /auth/verify.
-- See morok_relay/models.py:LoginLog for the privacy rationale.

CREATE TABLE IF NOT EXISTS login_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pubkey      BYTEA NOT NULL,
    created_at  BIGINT NOT NULL,
    ip_hash     VARCHAR(64) NOT NULL,
    user_agent  VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS ix_login_log_pubkey      ON login_log(pubkey);
CREATE INDEX IF NOT EXISTS ix_login_log_created_at  ON login_log(created_at);
