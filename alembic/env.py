"""
Alembic environment configuration.

Reads DB URL from our morok_relay.config.Settings (which loads from .env),
not from alembic.ini. This keeps all configuration in one place.

Notes:
- We import models so that `target_metadata` knows about all tables.
- We rewrite the async DSN to sync because alembic uses sync SQLAlchemy.
"""
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from morok_relay.config import get_settings
from morok_relay.db import Base
from morok_relay import models  # noqa: F401 — load models so metadata sees them

# Alembic Config object — gives access to alembic.ini values.
config = context.config

# Logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Inject our DB URL, converting async driver to sync (psycopg2-style) for Alembic.
settings = get_settings()
sync_dsn = settings.db_dsn.replace("postgresql+asyncpg://", "postgresql+psycopg2://")
config.set_main_option("sqlalchemy.url", sync_dsn)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations without a live DB connection (generates SQL)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against the live DB."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,         # detect column type changes
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
