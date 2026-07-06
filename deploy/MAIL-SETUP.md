# morok.email — фаза 1: розгортання (прийом)

## 0. Що це
SMTP-приймач: лист → шифрування (sealed box на pubkey власника) → черга
доставки relay (як звичайний sealed-конверт) → видалення після fetch.
Недоставлені живуть MOROK_MAIL_TTL_SECONDS (дефолт 7 діб).
Сервер не зберігає листи. Таблиця одна: mail_aliases.

## 1. .env — нові змінні (додати)
    MOROK_MAIL_DOMAIN=morok.email
    MOROK_MAIL_SMTP_PORT=25
    MOROK_MAIL_MAX_BYTES=26214400          # 25 MB
    MOROK_MAIL_RL_PER_IP=30                # листів/хв з одного IP
    MOROK_MAIL_TTL_SECONDS=604800          # 7 діб для недоставлених
    MOROK_MAIL_ALIAS_START=3               # аліасів одразу
    MOROK_MAIL_ALIAS_PER_MONTH=1           # прогрів
    MOROK_MAIL_ALIAS_CAP=15                # стеля
    MOROK_MAIL_ADMIN_PUBKEY_HEX=<твій pubkey hex>   # postmaster@/abuse@ → сюди

У config.py додай поля (у клас Settings, стиль наявних):
    mail_domain: str = Field(default="morok.email")
    mail_smtp_port: int = Field(default=25)
    mail_max_bytes: int = Field(default=26214400)
    mail_rl_per_ip: int = Field(default=30)
    mail_ttl_seconds: int = Field(default=604800)
    mail_alias_start: int = Field(default=3)
    mail_alias_per_month: int = Field(default=1)
    mail_alias_cap: int = Field(default=15)
    mail_admin_pubkey_hex: str = Field(default="")

## 2. main.py — підключити роутер
    from .api import mail            # додати до імпортів
    app.include_router(mail.router, prefix="/api/v1/mail")

## 3. Залежності
    pip install aiosmtpd==1.4.6 pyspf==2.0.14 dnspython
(pyspf опційний — без нього SPF="none", все працює)

## 4. Міграція БД (alembic або вручну)
    CREATE TYPE mail_alias_status AS ENUM ('active','paused','dead');
    CREATE TABLE mail_aliases (
      id UUID PRIMARY KEY,
      alias VARCHAR(64) NOT NULL UNIQUE,
      owner_pubkey BYTEA NOT NULL,
      status mail_alias_status NOT NULL DEFAULT 'active',
      is_primary BOOLEAN NOT NULL DEFAULT FALSE,
      created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
      received_count BIGINT NOT NULL DEFAULT 0
    );
    CREATE INDEX ix_mail_aliases_owner ON mail_aliases(owner_pubkey);
    CREATE INDEX ix_mail_aliases_status ON mail_aliases(status);

## 5. systemd
    sudo cp deploy/morok-mail.service /etc/systemd/system/
    sudo systemctl daemon-reload && sudo systemctl enable --now morok-mail
    journalctl -u morok-mail -f

## 6. DNS (Cloudflare, ВСЕ DNS-only/сірі хмарки — MX не проксіюється!)
    MX   morok.email  →  mail1.morok.email   пріоритет 10
    (пізніше failover: MX 20 → mail2...)
    A    mail1.morok.email → <IP нового вузла>
    TXT  morok.email        "v=spf1 -all"
         ; ми НЕ відправляємо — жорсткий анти-спуфінг. Коли буде фаза 3,
         ; заміниш на v=spf1 ip4:<outbound-IP> -all
    TXT  _dmarc.morok.email "v=DMARC1; p=reject; adkim=s; aspf=s"

## 7. Firewall на вузлі
    відкрити: 25/tcp (SMTP in), 22 (SSH). 443/80 — якщо тут же API.
    Вихідний 25 НЕ потрібен (фаза 1 не шле).

## 8. Тест
    1) створити аліас:  POST /api/v1/mail/aliases  (з клієнта чи curl із сесією)
    2) надіслати лист з Gmail на <alias>@morok.email
    3) journalctl: "mail: DATA ok, delivered=1"
    4) конверт з'явиться у черзі власника (kind=email усередині blob) —
       клієнт розшифровує tweetnacl sealed box → JSON (формат у mail_convert.py)
    5) неіснуюча адреса → Gmail отримає bounce "550 No such user" — так і треба
    6) paused-аліас → лист зникає, відправник бачить успіх

## 9. Що свідомо НЕ зроблено у фазі 1
    - відправка назовні (фаза 3, окремий IP)
    - морок↔морок листи (фаза 2 — чисті E2EE-конверти)
    - DKIM-перевірка вхідних (додамо; SPF уже є best-effort)
    - UI (наступна сесія: вкладка «Пошта» у веб-клієнті)
