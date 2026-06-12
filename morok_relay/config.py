"""
Application settings, loaded from environment variables (.env file).
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="MOROK_",
        extra="ignore",
    )

    # ----- Relay identity -----
    relay_name: str = Field(default="relay1.morok.app")
    relay_pubkey_hex: str = Field(default="")
    relay_privkey_hex: str = Field(default="")
    tor_onion_address: str = Field(
        default="",
        description="The .onion hostname for this relay (without scheme). "
                    "Set via MOROK_TOR_ONION_ADDRESS in .env. Surfaced via "
                    "/health so clients can opt into Tor.",
    )

    # ----- Storage -----
    blob_dir: Path = Field(default=Path("/var/lib/morok/blobs"))

    # ----- TTL / lifecycle -----
    message_ttl_hard_seconds: int = Field(default=86400)
    max_blob_bytes: int = Field(default=262144)
    username_cooldown_days: int = Field(default=30)

    # ----- DB / Redis -----
    db_dsn: str = Field(default="postgresql+asyncpg://morok@localhost/morok_relay")
    db_pool_size: int = Field(default=10)
    db_max_overflow: int = Field(default=5)
    redis_url: str = Field(default="redis://localhost:6379/0")
    redis_pool_size: int = Field(default=20)

    # ----- Mode -----
    is_production: bool = Field(default=True)
    debug: bool = Field(default=False)

    # ----- Rate limiting -----
    rate_limit_enabled: bool = Field(default=True)

    # Proxy IPs whose forwarded headers (X-Real-IP / X-Forwarded-For) we
    # trust. Direct connections from any OTHER source have their forwarded
    # headers IGNORED — otherwise anyone reaching uvicorn directly (past
    # nginx) could spoof X-Real-IP to bypass IP rate-limits and poison the
    # audit log. Comma-separated. Default: loopback only (standard nginx
    # reverse-proxy on the same host).
    trusted_proxy_ips: str = Field(default="127.0.0.1,::1")
    rate_limit_auth_per_minute: int = Field(default=10)
    rate_limit_messages_per_minute: int = Field(default=60)

    # Sealed Sender: ліміт відправки ПО delivery-токену (релей не знає
    # хто шле, але стримує як часто шлють конкретному одержувачу).
    rate_limit_sealed_per_minute: int = 30
    rate_limit_group_create_per_minute: int = Field(default=5)
    rate_limit_group_messages_per_minute: int = Field(default=30)
    rate_limit_dms_create_per_minute: int = Field(default=5)
    rate_limit_ws_connections_per_pubkey: int = Field(default=5)

    # ----- Admin dashboard -----
    admin_username: str = Field(
        default="",
        description="Admin panel login. Empty = admin panel disabled.",
    )
    admin_password_hash: str = Field(
        default="",
        description="Argon2id hash of admin password (from nacl.pwhash.str). "
                    "Generate: python -c \"import nacl.pwhash; "
                    "print(nacl.pwhash.str(b'YOURPASS').decode())\"",
    )
    admin_session_ttl_seconds: int = Field(default=3600)

    # ----- Web push (VAPID) -----
    # When `vapid_public_key_b64` is empty, push is silently disabled —
    # endpoints return 503 and the trigger function is a no-op. To enable:
    # run generate_vapid_keys.py once, drop the PEM where the path points,
    # and set the public key (base64url, ~88 chars) in MOROK_VAPID_PUBLIC_KEY_B64.
    vapid_public_key_b64: str = Field(default="")
    vapid_private_key_path: Path = Field(
        default=Path("/etc/morok/vapid_private.pem"),
        description="Path to VAPID private key in PEM format (EC P-256, PKCS8).",
    )
    vapid_subject: str = Field(
        default="mailto:morok.messenger@protonmail.com",
        description="VAPID `sub` claim — admin contact for push providers.",
    )

    # Firebase Cloud Messaging (нативні Android-пуші). Вимкнено, поки
    # файла немає. Service-account JSON з Firebase Console:
    # Project Settings -> Service accounts -> Generate new private key.
    fcm_service_account_path: Path = Field(
        default=Path("/etc/morok/fcm-service-account.json"),
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
