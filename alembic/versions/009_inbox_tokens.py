"""
Inbox delivery tokens for Sealed Sender.

A recipient registers sha256-hashes of secret tokens they hand out to
their contacts (over E2EE). A sealed envelope (no `from`, no outer
signature) is accepted only when accompanied by a token whose hash is
registered for the recipient — anti-spam without the relay ever
learning WHO among the recipient's contacts is sending.

We keep up to 2 hashes per user (current + previous) so token rotation
doesn't instantly break in-flight senders.

Revision ID: 009_inbox_tokens
Revises: 008_push_platform
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "009_inbox_tokens"
down_revision = "008_push_platform"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "inbox_tokens",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("pubkey", sa.LargeBinary(length=32), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.UniqueConstraint("token_hash", name="uq_inbox_tokens_token_hash"),
    )
    op.create_index("ix_inbox_tokens_pubkey", "inbox_tokens", ["pubkey"])


def downgrade() -> None:
    op.drop_index("ix_inbox_tokens_pubkey", table_name="inbox_tokens")
    op.drop_table("inbox_tokens")
