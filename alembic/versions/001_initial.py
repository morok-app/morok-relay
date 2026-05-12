"""initial schema

Revision ID: 001_initial
Revises:
Create Date: 2026-05-11

Creates the v0.1 schema:
- users (Ed25519 pubkey-identified users)
- username_history (cooldown tracking)
- groups, group_members
- federation_peers

Mirrors morok_relay/models.py exactly. If you change models, generate
a new revision rather than editing this one.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ============================================================
    # users
    # ============================================================
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "pubkey", sa.LargeBinary(length=32), nullable=False,
            comment="Ed25519 public key — the user's permanent identity.",
        ),
        sa.Column(
            "username", sa.String(length=20), nullable=True,
            comment="Optional human-readable handle. Globally unique across federation.",
        ),
        sa.Column(
            "home_relay", sa.String(length=255), nullable=False,
            comment="Hostname of the relay where this user resides.",
        ),
        sa.Column(
            "created_at", sa.BigInteger(), nullable=False,
            server_default=sa.text("EXTRACT(epoch FROM now())"),
        ),
        sa.Column(
            "last_seen_at", sa.BigInteger(), nullable=True,
            comment="Last time this user connected. Used only for online indicator.",
        ),
        sa.Column("deleted_at", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("pubkey", name="uq_users_pubkey"),
        sa.UniqueConstraint("username", name="uq_users_username"),
    )
    op.create_index("ix_users_pubkey", "users", ["pubkey"])
    op.create_index("ix_users_username", "users", ["username"])

    # ============================================================
    # username_history
    # ============================================================
    op.create_table(
        "username_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("username", sa.String(length=20), nullable=False),
        sa.Column("pubkey", sa.LargeBinary(length=32), nullable=False),
        sa.Column("claimed_at", sa.BigInteger(), nullable=False),
        sa.Column("released_at", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_username_history_username", "username_history", ["username"])
    op.create_index(
        "ix_username_history_username_released",
        "username_history",
        ["username", "released_at"],
    )

    # ============================================================
    # groups
    # ============================================================
    op.create_table(
        "groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("creator_pubkey", sa.LargeBinary(length=32), nullable=False),
        sa.Column("name_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column(
            "is_channel", sa.Boolean(), nullable=False,
            server_default=sa.false(),
            comment="If True, only admins can post (read-only for members).",
        ),
        sa.Column(
            "default_ttl_seconds", sa.Integer(), nullable=False,
            server_default=sa.text("86400"),
            comment="Default disappearing-message TTL for this group.",
        ),
        sa.Column(
            "created_at", sa.BigInteger(), nullable=False,
            server_default=sa.text("EXTRACT(epoch FROM now())"),
        ),
        sa.Column("deleted_at", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_groups_creator_pubkey", "groups", ["creator_pubkey"])

    # ============================================================
    # group_members
    # ============================================================
    op.create_table(
        "group_members",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("group_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("pubkey", sa.LargeBinary(length=32), nullable=False),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "joined_at", sa.BigInteger(), nullable=False,
            server_default=sa.text("EXTRACT(epoch FROM now())"),
        ),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("group_id", "pubkey", name="uq_group_members_group_pubkey"),
    )
    op.create_index("ix_group_members_group_id", "group_members", ["group_id"])
    op.create_index("ix_group_members_pubkey", "group_members", ["pubkey"])

    # ============================================================
    # federation_peers
    # ============================================================
    op.create_table(
        "federation_peers",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column(
            "pubkey", sa.LargeBinary(length=32), nullable=False,
            comment="Relay's Ed25519 public key for federation auth.",
        ),
        sa.Column(
            "is_trusted", sa.Boolean(), nullable=False, server_default=sa.false(),
            comment="Operator-curated trust flag. Untrusted peers are rate-limited.",
        ),
        sa.Column("last_handshake_at", sa.BigInteger(), nullable=True),
        sa.Column(
            "created_at", sa.BigInteger(), nullable=False,
            server_default=sa.text("EXTRACT(epoch FROM now())"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("hostname", name="uq_federation_peers_hostname"),
    )


def downgrade() -> None:
    op.drop_table("federation_peers")
    op.drop_table("group_members")
    op.drop_table("groups")
    op.drop_table("username_history")
    op.drop_table("users")
