"""
users.username_changed_at — момент останньої явної зміни username
(аудит зовн. №3, HIGH — namespace squatting захист).

ЧОМУ ОКРЕМА КОЛОНКА, А НЕ UsernameHistory: історія записує лише
ЗВІЛЬНЕННЯ попереднього імені — для першого claim (нема що звільняти)
запис не з'являється, тож "коли я востаннє міняв ім'я" не можна
надійно вирахувати з history-таблиці одну.

Ідемпотентно (як 011_mail_tables): на relay1/relay2 схема інколи
правилась руками до відповідної Alembic-міграції, тому перевіряємо
наявність колонки перед додаванням.

Revision ID: 012_username_changed_at
Revises: 011_mail_tables
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "012_username_changed_at"
down_revision = "011_mail_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_cols = {c["name"] for c in inspector.get_columns("users")}
    if "username_changed_at" not in existing_cols:
        op.add_column(
            "users",
            sa.Column("username_changed_at", sa.BigInteger(), nullable=True),
        )


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_cols = {c["name"] for c in inspector.get_columns("users")}
    if "username_changed_at" in existing_cols:
        op.drop_column("users", "username_changed_at")
