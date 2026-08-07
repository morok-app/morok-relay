"""
morok.email — таблиці аліасів і черги вихідної пошти.

ЧОМУ ЦЯ МІГРАЦІЯ З'ЯВИЛАСЬ ПІЗНО: mail_aliases і mail_outbound були
описані в mail_models.py і створювались на працюючих релеях вручну, але
жодна міграція їх не створювала. Тому на СВІЖОМУ розгортанні
(deploy/install.sh → alembic upgrade head) поштові таблиці просто не
з'являлись, і morok.email падав на першому ж запиті. Ця міграція закриває
розрив між моделями та схемою.

ІДЕМПОТЕНТНІСТЬ — обов'язкова тут, а не «про всяк випадок»: на relay1 і
relay2 таблиці та enum-типи ВЖЕ існують (створені руками). Якби міграція
просто робила CREATE TABLE, вона впала б на цих серверах і заблокувала
всі наступні міграції. Тому кожен крок перевіряє наявність об'єкта.

Revision ID: 011_mail_tables
Revises: 010_inbox_token_unique
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "011_mail_tables"
down_revision = "010_inbox_token_unique"
branch_labels = None
depends_on = None


def _table_exists(name: str) -> bool:
    bind = op.get_bind()
    return sa.inspect(bind).has_table(name)


def upgrade() -> None:
    # ── enum-типи ──
    # DO $$ ... $$ замість CREATE TYPE, бо CREATE TYPE IF NOT EXISTS у
    # PostgreSQL не існує, а падіння тут заблокувало б міграцію на
    # серверах, де тип уже створено руками.
    op.execute(
        """
        DO $$ BEGIN
            CREATE TYPE mail_alias_status AS ENUM ('active', 'paused', 'dead');
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
        """
    )
    op.execute(
        """
        DO $$ BEGIN
            CREATE TYPE mail_outbound_status AS ENUM
                ('queued', 'sending', 'delivered', 'failed');
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
        """
    )

    alias_status = postgresql.ENUM(
        "active", "paused", "dead",
        name="mail_alias_status",
        create_type=False,
    )
    outbound_status = postgresql.ENUM(
        "queued", "sending", "delivered", "failed",
        name="mail_outbound_status",
        create_type=False,
    )

    # ── mail_aliases ──
    if not _table_exists("mail_aliases"):
        op.create_table(
            "mail_aliases",
            sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column(
                "alias", sa.String(length=64), nullable=False,
                comment="Local-part адреси без домену.",
            ),
            sa.Column(
                "owner_pubkey", sa.LargeBinary(length=32), nullable=False,
                comment="Власник аліаса.",
            ),
            sa.Column(
                "status", alias_status, nullable=False,
                server_default="active",
                comment="active приймає; paused тихо дропає (SMTP 250); "
                        "dead відмовляє (550) і НІКОЛИ не перевикористовується.",
            ),
            sa.Column(
                "is_primary", sa.Boolean(), nullable=False,
                server_default="false",
                comment="Основна адреса = нік користувача. Не витрачає квоту.",
            ),
            sa.Column(
                "label", sa.String(length=64), nullable=True,
                comment="Підпис «для чого» — фіча «хто злив адресу».",
            ),
            sa.Column(
                "created_at", sa.BigInteger(), nullable=False,
                server_default=sa.text("EXTRACT(epoch FROM now())"),
            ),
            sa.Column(
                "received_count", sa.BigInteger(), nullable=False,
                server_default="0",
                comment="Лічильник прийнятих листів. Без метаданих.",
            ),
            sa.PrimaryKeyConstraint("id"),
            # Унікальність alias — не лише зручність: мертві аліаси
            # лишаються в таблиці саме щоб адресу не перереєстрував хтось
            # інший і не отримував чужу пошту (анти-фішинг).
            sa.UniqueConstraint("alias", name="uq_mail_aliases_alias"),
        )
        op.create_index("ix_mail_aliases_alias", "mail_aliases", ["alias"])
        op.create_index(
            "ix_mail_aliases_owner_pubkey", "mail_aliases", ["owner_pubkey"],
        )
        op.create_index("ix_mail_aliases_status", "mail_aliases", ["status"])

    # ── mail_outbound ──
    if not _table_exists("mail_outbound"):
        op.create_table(
            "mail_outbound",
            sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("owner_pubkey", sa.LargeBinary(length=32), nullable=False),
            sa.Column("from_alias", sa.String(length=64), nullable=False),
            sa.Column("to_addr", sa.String(length=255), nullable=False),
            sa.Column("subject", sa.String(length=998), nullable=True),
            sa.Column(
                "body_text", sa.String(), nullable=True,
                comment="Стирається (NULL) після доставки — приватність.",
            ),
            sa.Column(
                "attachments_json", sa.String(), nullable=True,
                comment="JSON [{filename, content_type, b64}]; стирається разом із тілом.",
            ),
            sa.Column("in_reply_to", sa.String(length=256), nullable=True),
            sa.Column("references_hdr", sa.String(length=2048), nullable=True),
            sa.Column(
                "status", outbound_status, nullable=False,
                server_default="queued",
            ),
            sa.Column(
                "attempts", sa.BigInteger(), nullable=False, server_default="0",
            ),
            sa.Column("last_error", sa.String(length=500), nullable=True),
            sa.Column("created_at", sa.BigInteger(), nullable=False),
            sa.Column("updated_at", sa.BigInteger(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_mail_outbound_owner_pubkey", "mail_outbound", ["owner_pubkey"],
        )
        op.create_index("ix_mail_outbound_status", "mail_outbound", ["status"])


def downgrade() -> None:
    # Знімаємо тільки те, що справді є: на серверах, де таблиці створювались
    # руками, downgrade не має падати.
    if _table_exists("mail_outbound"):
        op.drop_table("mail_outbound")
    if _table_exists("mail_aliases"):
        op.drop_table("mail_aliases")
    op.execute("DROP TYPE IF EXISTS mail_outbound_status")
    op.execute("DROP TYPE IF EXISTS mail_alias_status")
