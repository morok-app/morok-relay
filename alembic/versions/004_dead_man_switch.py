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

Note on the enum
----------------
We create the `dms_status` enum type via op.execute(CREATE TYPE), and reference
it from the table column with postgresql.ENUM(..., create_type=False) so that
SQLAlchemy's before_create hook does NOT try to recreate the type a second
time (which would fail with DuplicateObject). This is the standard alembic
+ postgres enum pattern.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "004_dead_man_switch"
down_revision: Union[str, None] = "003_groups_extended"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create the enum TYPE explicitly. create_type=False on the column
    # below ensures SQLAlchemy won't try to create it again.
    op.execute(
        "CREATE TYPE dms_status AS ENUM ('armed', 'triggered', 'cancelled')"
    )

    dms_status_enum = postgresql.ENUM(
        "armed", "triggered", "cancelled",
        name="dms_status",
        create_type=False,   # prevents re-creation when used in columns
    )

    op.create_table(
        "dead_man_switches",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "creator_pubkey", sa.LargeBinary(length=32), nullable=False,
            comment="Owner of the DMS.",
        ),
        sa.Column(
            "trigger_seconds", sa.Integer(), nullable=False,
            comment="Inactivity period before trigger. 3600 to 31536000.",
        ),
        sa.Column(
            "last_check_in_at", sa.BigInteger(), nullable=False,
            comment="Epoch seconds of last activity.",
        ),
        sa.Column(
            "payload_encrypted", sa.LargeBinary(), nullable=False,
            comment="Ciphertext to deliver on trigger. Max 256 KB.",
        ),
        sa.Column(
            "label", sa.String(length=100), nullable=True,
            comment="User-visible label like 'family' or 'work'.",
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
        ),
        sa.Column(
            "delivered_at", sa.BigInteger(), nullable=True,
            comment="Epoch second when trigger delivered to this recipient.",
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
    op.execute("DROP TYPE dms_status")
