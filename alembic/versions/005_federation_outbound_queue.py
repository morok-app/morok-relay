"""federation outbound queue

Revision ID: 005_federation_outbound
Revises: 004_dead_man_switch
Create Date: 2026-05-20

Adds federation_outbound_queue: durable retry queue for envelopes that
need to be forwarded to other relays in the federation.

Status enum: pending -> in_flight -> succeeded | dead_letter

Worker picks up pending rows where next_attempt_at <= now, marks them
in_flight, attempts remote_forward, and either marks succeeded or
schedules the next retry with exponential backoff.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = "005_federation_outbound"
down_revision = "004_dead_man_switch"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create enum first (idempotent — if it exists, that's fine for our
    # threat model, but we use create_type=False on the column to avoid
    # double-creation if alembic re-runs after a partial failure).
    fed_queue_status = postgresql.ENUM(
        "pending", "in_flight", "succeeded", "dead_letter",
        name="fed_queue_status",
    )
    fed_queue_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "federation_outbound_queue",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("envelope_id", sa.String(64), nullable=False),
        sa.Column("envelope_data", postgresql.JSONB, nullable=False),
        sa.Column("target_relay", sa.String(255), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(
                "pending", "in_flight", "succeeded", "dead_letter",
                name="fed_queue_status",
                create_type=False,
            ),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.BigInteger, nullable=False),
        sa.Column("last_error", sa.Text, nullable=True),
        sa.Column("created_at", sa.BigInteger, nullable=False),
        sa.Column("delivered_at", sa.BigInteger, nullable=True),
    )

    # Indexes for worker query and dedup/monitoring
    op.create_index(
        "ix_fed_queue_status_next_attempt",
        "federation_outbound_queue",
        ["status", "next_attempt_at"],
    )
    op.create_index(
        "ix_fed_queue_envelope_id",
        "federation_outbound_queue",
        ["envelope_id"],
    )
    op.create_index(
        "ix_fed_queue_target_status",
        "federation_outbound_queue",
        ["target_relay", "status"],
    )


def downgrade() -> None:
    op.drop_index("ix_fed_queue_target_status", "federation_outbound_queue")
    op.drop_index("ix_fed_queue_envelope_id", "federation_outbound_queue")
    op.drop_index("ix_fed_queue_status_next_attempt", "federation_outbound_queue")
    op.drop_table("federation_outbound_queue")

    fed_queue_status = postgresql.ENUM(
        "pending", "in_flight", "succeeded", "dead_letter",
        name="fed_queue_status",
    )
    fed_queue_status.drop(op.get_bind(), checkfirst=True)
