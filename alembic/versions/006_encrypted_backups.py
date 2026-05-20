"""encrypted key backup

Revision ID: 006_encrypted_backups
Revises: 005_federation_outbound
Create Date: 2026-05-20

Adds encrypted_backups: a single zero-knowledge encrypted-seed blob per
pubkey. Premium feature. Relay never sees plaintext seed.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "006_encrypted_backups"
down_revision = "005_federation_outbound"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "encrypted_backups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("pubkey", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("username_at_backup", sa.String(20), nullable=True, index=True),
        sa.Column("encrypted_seed", sa.LargeBinary, nullable=False),
        sa.Column("kdf_salt", sa.LargeBinary(16), nullable=False),
        sa.Column(
            "kdf_params",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("schema_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("created_at", sa.BigInteger, nullable=False),
        sa.Column("updated_at", sa.BigInteger, nullable=False),
    )

    op.create_index(
        "ix_encrypted_backups_pubkey",
        "encrypted_backups",
        ["pubkey"],
    )


def downgrade() -> None:
    op.drop_index("ix_encrypted_backups_pubkey", "encrypted_backups")
    op.drop_table("encrypted_backups")
