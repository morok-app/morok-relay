"""
morok.email — модель аліасів.

Одна таблиця: mail_aliases. Сервер зберігає ТІЛЬКИ маршрутизацію
(alias → owner_pubkey) і стан. Жодних листів, жодних логів листування.

Стани:
    active — приймає пошту
    paused — листи тихо дропаються (SMTP 250, лист у смітник) —
             відправник не знає, що його відрізали
    dead   — SMTP 550, адреса не існує; запис лишається, щоб адресу
             не міг перереєструвати хтось інший (анти-phishing)

Прогрів (анти-абуза, рахується в api/mail.py):
    на старті: 1 primary + MAIL_ALIAS_START (3)
    далі:      +MAIL_ALIAS_PER_MONTH (1) за кожен повний місяць
               життя акаунта, до стелі MAIL_ALIAS_CAP (15)
"""
from __future__ import annotations

import enum
import uuid

from sqlalchemy import BigInteger, Boolean, LargeBinary, String, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class AliasStatus(str, enum.Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    DEAD = "dead"


class MailAlias(Base):
    __tablename__ = "mail_aliases"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # local-part адреси, без домену: "hushed-crane-042"
    alias: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    owner_pubkey: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, index=True
    )
    status: Mapped[AliasStatus] = mapped_column(
        SAEnum(
            AliasStatus,
            name="mail_alias_status",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
        default=AliasStatus.ACTIVE,
        server_default="active",
        index=True,
    )
    is_primary: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # користувацький підпис «для чого цей аліас» (netflix, олх...) —
    # серцевина фічі «хто злив адресу»: спам на аліас → підпис каже, хто продав
    label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False,
        server_default=func.extract("epoch", func.now()),
    )
    # лічильник прийнятих листів (тільки число, без метаданих) —
    # користувачу видно "скільки прилетіло", серверу — патерни абузи
    received_count: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )


class OutboundStatus(str, enum.Enum):
    QUEUED = "queued"
    SENDING = "sending"
    DELIVERED = "delivered"
    FAILED = "failed"


class MailOutbound(Base):
    """
    Черга вихідних ЗОВНІШНІХ листів (morok → великий світ).

    Приватність: body_text/subject живуть тут ЛИШЕ до доставки. Щойно
    воркер відзвітував delivered/failed — вміст стирається (NULL),
    лишаються метадані статусу, щоб юзер бачив ✓/✗ у «Відправлених».
    """
    __tablename__ = "mail_outbound"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    owner_pubkey: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, index=True
    )
    from_alias: Mapped[str] = mapped_column(String(64), nullable=False)
    to_addr: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str | None] = mapped_column(String(998), nullable=True)
    body_text: Mapped[str | None] = mapped_column(String, nullable=True)
    # JSON-масив вкладень [{filename, content_type, b64}] — стирається
    # разом із body_text після доставки (приватність)
    attachments_json: Mapped[str | None] = mapped_column(String, nullable=True)
    # тредінг: заголовки для склеювання ланцюжків у зовнішніх поштах
    in_reply_to: Mapped[str | None] = mapped_column(String(256), nullable=True)
    references_hdr: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    status: Mapped[OutboundStatus] = mapped_column(
        SAEnum(OutboundStatus, name="mail_outbound_status",
               values_callable=lambda e: [m.value for m in e]),
        nullable=False, default=OutboundStatus.QUEUED, index=True,
    )
    attempts: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    updated_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
