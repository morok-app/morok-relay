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

    # ----- Storage -----
    blob_dir: Path = Field(default=Path("/var/lib/morok/blobs"))

    # ----- TTL / lifecycle -----
    message_ttl_hard_seconds: int = Field(default=86400)
    max_blob_bytes: int = Field(default=262144)
    username_cooldown_days: int = Field(default=30)

    # ----- DB / Redis -----
    db_dsn: str = Field(default="postgresql+asyncpg://morok@localhost/morok_relay")
    redis_url: str = Field(default="redis://localhost:6379/0")

    # ----- Mode -----
    is_production: bool = Field(default=True)
    debug: bool = Field(default=False)

    # ----- Rate limiting (NEW in v0.8) -----
    rate_limit_enabled: bool = Field(
        default=True,
        description="Master toggle. Set false to disable all rate limiting "
                    "(useful for local dev / running the e2e test client).",
    )
    rate_limit_auth_per_minute: int = Field(
        default=10,
        description="Per-IP limit on /auth/challenge and /auth/verify.",
    )
    rate_limit_messages_per_minute: int = Field(
        default=60,
        description="Per-pubkey limit on POST /api/v1/messages.",
    )
    rate_limit_group_create_per_minute: int = Field(
        default=5,
        description="Per-pubkey limit on POST /api/v1/groups (create new).",
    )
    rate_limit_group_messages_per_minute: int = Field(
        default=30,
        description="Per-pubkey limit on POST /api/v1/groups/{id}/messages.",
    )
    rate_limit_dms_create_per_minute: int = Field(
        default=5,
        description="Per-pubkey limit on POST /api/v1/dms.",
    )
    rate_limit_ws_connections_per_pubkey: int = Field(
        default=5,
        description="Max concurrent WebSocket connections per pubkey.",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
