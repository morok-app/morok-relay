"""add home_relay column to groups (cross-relay groups support)

Revision ID: 007_group_home_relay
Revises: 006_encrypted_backups
Create Date: 2026-05-25

A group lives in exactly one relay's database — its "home". Members
on other relays route their sends through federation; the host relay
fans out locally and re-federates to relays that have remote members.

Existing groups (created before this migration) are assumed to be
hosted by the relay running this migration — we backfill from
settings.relay_name.

We keep the column NULLABLE so that any unmigrated rows / future legacy
data still load; server-side code falls back to `settings.relay_name`
when `group.home_relay is None`. New rows always set it explicitly.
"""
from alembic import op
import sqlalchemy as sa


revision = "007_group_home_relay"
down_revision = "006_encrypted_backups"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "groups",
        sa.Column("home_relay", sa.String(length=255), nullable=True),
    )

    # Backfill existing rows. Try to read the current relay name from
    # settings; on any failure fall back to NULL (server treats NULL as
    # "this relay" via runtime fallback).
    try:
        from morok_relay.config import get_settings
        relay_name = get_settings().relay_name
    except Exception:
        relay_name = None

    if relay_name:
        op.execute(
            sa.text(
                "UPDATE groups SET home_relay = :rn WHERE home_relay IS NULL"
            ).bindparams(rn=relay_name)
        )

    op.create_index(
        "ix_groups_home_relay",
        "groups",
        ["home_relay"],
    )


def downgrade() -> None:
    op.drop_index("ix_groups_home_relay", table_name="groups")
    op.drop_column("groups", "home_relay")
