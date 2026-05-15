"""extend groups: slug, expires_at, anonymous_senders, max_members

Revision ID: 003_groups_extended
Revises: 002_user_tier
Create Date: 2026-05-14

Adds to `groups`:
- slug (varchar 30, nullable, unique) — custom URL handle for channels.
  Only premium users can set this. Format: 3-20 chars, a-z 0-9 _.
- expires_at (bigint, nullable) — if set, the group is deleted after this
  epoch second. Powers "chats with a predetermined end".
- anonymous_senders (bool, default false) — when true, member messages
  to the group are presented as from the group itself, not the sender.
  See docs/API.md for the exact privacy boundary (relay still sees sender).
- max_members (int, default 50) — enforced on join. Free tier creators
  get 50; premium creators get 200. Setting is recorded at creation time
  and doesn't change if the creator's tier changes later.

No changes to other tables.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003_groups_extended"
down_revision: Union[str, None] = "002_user_tier"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "groups",
        sa.Column(
            "slug",
            sa.String(length=30),
            nullable=True,
            comment="Custom URL handle for channels (premium feature).",
        ),
    )
    op.create_index("ix_groups_slug", "groups", ["slug"], unique=True)

    op.add_column(
        "groups",
        sa.Column(
            "expires_at",
            sa.BigInteger(),
            nullable=True,
            comment="If set, group is deleted after this epoch second.",
        ),
    )
    op.create_index("ix_groups_expires_at", "groups", ["expires_at"])

    op.add_column(
        "groups",
        sa.Column(
            "anonymous_senders",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
            comment="If true, members appear as the group itself, not themselves.",
        ),
    )

    op.add_column(
        "groups",
        sa.Column(
            "max_members",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("50"),
            comment="Member cap (50 free / 200 premium at creation time).",
        ),
    )


def downgrade() -> None:
    op.drop_column("groups", "max_members")
    op.drop_column("groups", "anonymous_senders")
    op.drop_index("ix_groups_expires_at", table_name="groups")
    op.drop_column("groups", "expires_at")
    op.drop_index("ix_groups_slug", table_name="groups")
    op.drop_column("groups", "slug")
