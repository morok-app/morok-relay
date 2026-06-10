"""
Add `platform` to push_subscriptions: 'webpush' (browser, VAPID) or
'fcm' (native Android, Firebase Cloud Messaging).

For FCM rows `endpoint` holds the FCM device token and p256dh/auth are
empty strings (they're RFC 8291 keys, meaningless for FCM).

Revision ID: 008_push_platform
Revises: 007_group_home_relay
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "008_push_platform"
down_revision = "007_group_home_relay"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "push_subscriptions",
        sa.Column(
            "platform",
            sa.String(length=16),
            nullable=False,
            server_default="webpush",
        ),
    )


def downgrade() -> None:
    op.drop_column("push_subscriptions", "platform")
