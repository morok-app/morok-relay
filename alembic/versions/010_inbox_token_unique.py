"""
Fix inbox_tokens uniqueness: (pubkey, token_hash) instead of global
token_hash.

The semantic key of a Sealed Sender delivery-token registration is the
PAIR (recipient, hash) — the sealed-send lookup in api/sealed.py filters
by both columns. A global unique on token_hash alone meant that if two
different users ever registered the same hash (vanishingly unlikely with
random 32-byte tokens, but not impossible), the second registration
would fail with an IntegrityError. The composite constraint also lets
the (pubkey, token_hash) lookup use a single covering index.

Revision ID: 010_inbox_token_unique
Revises: 009_inbox_tokens
"""
from __future__ import annotations

from alembic import op

revision = "010_inbox_token_unique"
down_revision = "009_inbox_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        "uq_inbox_tokens_token_hash", "inbox_tokens", type_="unique",
    )
    op.create_unique_constraint(
        "uq_inbox_tokens_pubkey_token_hash",
        "inbox_tokens",
        ["pubkey", "token_hash"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_inbox_tokens_pubkey_token_hash", "inbox_tokens", type_="unique",
    )
    op.create_unique_constraint(
        "uq_inbox_tokens_token_hash", "inbox_tokens", ["token_hash"],
    )
