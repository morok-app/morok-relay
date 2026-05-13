"""add user tier

Revision ID: 002_user_tier
Revises: 001_initial
Create Date: 2026-05-13

Adds a 'tier' enum column to users:
- 'free'    (default)  → username 5+ chars
- 'premium' (paid)     → username 3+ chars
- 'admin'   (manual)   → any username including 1-2 chars

Tier is set server-side. Free users cannot change their own tier.
Premium tier is reserved for future monetization (no admin UI yet — must
update directly in DB or via internal script).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002_user_tier"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Postgres enum type — created once, referenced by column.
user_tier_enum = sa.Enum("free", "premium", "admin", name="user_tier")


def upgrade() -> None:
    user_tier_enum.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "users",
        sa.Column(
            "tier",
            user_tier_enum,
            nullable=False,
            server_default="free",
            comment="Account tier: free (5+ char usernames), premium (3+), admin (1+).",
        ),
    )
    # Index for filtering by tier — useful when running stats or batch promote
    op.create_index("ix_users_tier", "users", ["tier"])


def downgrade() -> None:
    op.drop_index("ix_users_tier", table_name="users")
    op.drop_column("users", "tier")
    user_tier_enum.drop(op.get_bind(), checkfirst=True)
