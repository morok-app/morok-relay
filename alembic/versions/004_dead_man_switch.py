"""add dead_man_switches and dms_recipients

Revision ID: 004_dead_man_switch
Revises: 003_groups_extended
Create Date: 2026-05-17

Adds two new tables:

- dead_man_switches: stores each user's DMS configuration.
  - creator_pubkey: the user who owns this switch
  - trigger_seconds: 3600 (1h) to 31536000 (1 year)
  - last_check_in_at: epoch second of last "I'm alive" signal.
    Updated either by explicit check-in or any authenticated request.
  - payload_encrypted: ciphertext to send to each recipient on trigger.
    Encrypted client-side; relay never sees plaintext.
  - status: armed | triggered | cancelled
  - triggered_at: when the cron actually fired this switch
  - cancelled_at: when the user manually cancelled

- dms_recipients: many-to-many. Each switch has 1-20 recipients.
  Stored as a separate table (not array) so we can index and query.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "004_dead_man_switch"
down_revision: Union[str, None] = "003_groups_extended"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


dms_status_enum = sa.Enum("armed", "triggered", "cancelled", name="dms_status")


def upgrade() -> None:
    dms_status_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "dead_man_switches",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "creator_pubkey", sa.LargeBinary(length=32), nullable=False,
            comment="Owner of the DMS. Updates flow via session's pubkey.",
        ),
        sa.Column(
            "trigger_seconds", sa.Integer(), nullable=False,
            comment="Inactivity period before trigger. 3600 to 31536000.",
        ),
        sa.Column(
            "last_check_in_at", sa.BigInteger(), nullable=False,
            comment="Epoch seconds of last activity. Updated on each authenticated request.",
        ),
        sa.Column(
            "payload_encrypted", sa.LargeBinary(), nullable=False,
            comment="Ciphertext to deliver to each recipient on trigger. Max 256 KB.",
        ),
        sa.Column(
            "label", sa.String(length=100), nullable=True,
            comment="User-visible label like 'family' or 'work'. Encrypted client-side OR plaintext for indexing — caller's choice.",
        ),
        sa.Column(
            "status", dms_status_enum, nullable=False, server_default="armed",
        ),
        sa.Column(
            "created_at", sa.BigInteger(), nullable=False,
            server_default=sa.text("EXTRACT(epoch FROM now())"),
        ),
        sa.Column("triggered_at", sa.BigInteger(), nullable=True),
        sa.Column("cancelled_at", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_dms_creator_status", "dead_man_switches", ["creator_pubkey", "status"],
    )
    # Critical for the cron: find armed switches that should fire.
    op.create_index(
        "ix_dms_status_check_in", "dead_man_switches", ["status", "last_check_in_at"],
    )

    op.create_table(
        "dms_recipients",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "dms_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("dead_man_switches.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "recipient_pubkey", sa.LargeBinary(length=32), nullable=False,
            comment="Whom to deliver the payload to on trigger.",
        ),
        sa.Column(
            "delivered_at", sa.BigInteger(), nullable=True,
            comment="Epoch second when the trigger actually delivered to this recipient.",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dms_id", "recipient_pubkey", name="uq_dms_recipients"),
    )
    op.create_index(
        "ix_dms_recipients_dms_id", "dms_recipients", ["dms_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_dms_recipients_dms_id", table_name="dms_recipients")
    op.drop_table("dms_recipients")
    op.drop_index("ix_dms_status_check_in", table_name="dead_man_switches")
    op.drop_index("ix_dms_creator_status", table_name="dead_man_switches")
    op.drop_table("dead_man_switches")
    dms_status_enum.drop(op.get_bind(), checkfirst=True)
