"""
Centralized configuration loaded from environment variables.

All config flows through this module. Never read os.environ directly
elsewhere — that breaks testability and makes it hard to find what's
configurable.
"""
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="MOROK_",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # === Application ===
    env: Literal["development", "production"] = "development"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    relay_name: str = "relay-local.morok.app"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # === Database ===
    db_dsn: str
    db_pool_size: int = 10
    db_max_overflow: int = 20

    # === Redis ===
    redis_url: str = "redis://localhost:6379/0"
    redis_pool_size: int = 10

    # === Storage ===
    blob_dir: Path = Path("/var/lib/morok/blobs")

    # === Message TTL ===
    message_ttl_hard_seconds: int = Field(default=172800, ge=3600, le=604800)

    # === Federation ===
    relay_pubkey_hex: str = ""
    relay_privkey_hex: str = ""
    known_relays: str = ""

    # === Security ===
    max_blob_bytes: int = Field(default=262144, ge=1024, le=10_485_760)
    rate_limit_per_min: int = 60
    rate_limit_burst: int = 10

    # === Username ===
    username_min_len: int = 3
    username_max_len: int = 20
    username_cooldown_days: int = 30

    @field_validator("relay_privkey_hex")
    @classmethod
    def validate_privkey(cls, v: str, info) -> str:
        """In production, relay must have a keypair configured."""
        env = info.data.get("env", "development")
        if env == "production" and not v:
            raise ValueError(
                "MOROK_RELAY_PRIVKEY_HEX must be set in production. "
                "Generate with: python -m morok_relay.scripts.generate_relay_keypair"
            )
        return v

    @property
    def known_relays_list(self) -> list[str]:
        """Parsed list of known relay hostnames."""
        return [r.strip() for r in self.known_relays.split(",") if r.strip()]

    @property
    def is_production(self) -> bool:
        return self.env == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Cached settings instance. Use this everywhere instead of instantiating
    Settings() directly — that way tests can override via dependency injection.
    """
    return Settings()  # type: ignore[call-arg]
