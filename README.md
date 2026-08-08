# morok-relay

Бекенд Morok: API, WebSocket-інбокс, федерація між релеями, morok.email.

**Це робоча пам'ятка, а не презентація.** Тут те, що забувається за півроку:
де що лежить, як деплоїться і що ламається, якщо зробити неправильно.

---

## Стек

Python 3.12 · FastAPI (async) · PostgreSQL 16 · Redis 7 · PyNaCl

Релей ніколи не бачить відкритого тексту й не має приватних ключів
користувачів. Зашифровані блоби лежать у черзі доставки й фізично
затираються після доставки або протермінування.

---

## Сервери

| | адреса | що крутиться |
|---|---|---|
| **relay1** | `root@62.238.28.107` (Hetzner, hostname `vibra-tor-prod`) | API/WS, веб-клієнт, admin, **morok-mail** (вхідний SMTP) |
| **relay2** | `root@167.86.120.176` (Contabo, hostname `vmi3308392`) | API/WS, веб-клієнт |
| **cx23** | `root@77.42.19.151` | **вихідна пошта** (mail_out.py, забирає з `/api/v1/mail/outbound/claim`) |

Код релея на обох relay-серверах: `/home/morok/morok-relay`

### systemd

Сервіси:
```
morok-relay.service     API + WebSocket
morok-mail.service      вхідний SMTP, порт 25 (тільки relay1)
```

Таймери (їх **не видно** в `systemctl list-units --type=service`, бо
`Type=oneshot` — дивитись через `list-timers`):
```
morok-reaper.timer             щогодини — затирає доставлені/протухлі блоби
morok-dms-reaper.timer         «цифровий заповіт»
morok-federation-worker.timer  щохвилини — черга федерації
morok-fstrim.timer             щоночі — БЕЗ нього secure-delete на SSD не дотирає
```

```bash
systemctl list-timers --all | grep -i morok
```

---

## Деплой

```bash
cd /home/morok/morok-relay && git pull && systemctl restart morok-relay
```

Якщо була міграція:
```bash
.venv/bin/alembic upgrade head && systemctl restart morok-relay
```

**Обидва relay-сервери оновлювати разом.** Розсинхрон версій ламає федерацію
тихо й непередбачувано.

### Deploy keys

У кожного сервера **свій** ключ, прив'язаний до цього репозиторія
(GitHub не дозволяє один deploy key на два репо, але дозволяє два ключі
на одне). Перевірка:

```bash
ssh -T git@github.com     # має відповісти "Hi morok-app/morok-relay!"
```

Якщо відповідає іншим репо — ключ від чужого проєкту. Лікується так:

```bash
ssh-keygen -t ed25519 -C "relayN-morok-relay" -f ~/.ssh/morok_relay_deploy -N ""
cat ~/.ssh/morok_relay_deploy.pub    # → GitHub → repo → Settings → Deploy keys
cat >> ~/.ssh/config <<'EOF'

Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/morok_relay_deploy
    IdentitiesOnly yes
EOF
chmod 600 ~/.ssh/config
```

`IdentitiesOnly yes` обов'язковий — інакше ssh перебере всі ключі й
підсуне не той.

---

## Підводні камені

**`.env` не в git і НЕ МАЄ туди потрапити.** Він лежить поруч із кодом на
серверах. Тому чистка робочої копії тільки так:

```bash
git clean -fd -e .env -e .venv/
```

Голий `git clean -fd` зносить `.env` і кладе релей.

**Нові моделі треба реєструвати в `alembic/env.py`.** Якщо цього не зробити,
autogenerate їх не побачить і таблиці не потраплять у міграції — саме так
`mail_aliases`/`mail_outbound` колись випали й пошта не працювала на
свіжому розгортанні.

**Міграції на працюючих серверах мають бути ідемпотентні.** Частина таблиць
там створена руками; звичайний `CREATE TABLE` упаде й **заблокує всі
наступні міграції**.

**Секрети в шляхах URL не логувати.** Burner-токен сам є доступом — хто
прочитає лог, той може писати від імені будь-якого анонімного відправника.
Маскування в `main.py`, `_sanitize_path()`.

---

## TTL

| що | скільки | де |
|---|---|---|
| повідомлення | 24 год | `message_ttl_hard_seconds` |
| пошта | 7 діб | `mail_ttl_seconds` |

Reaper спершу питає чергу Redis і лише потім дивиться на вік файлу.
Порядок важливий: навпаки — поштові блоби гинули б на 25-й годині.

---

## Локальний запуск

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # заповнити
alembic upgrade head
uvicorn morok_relay.main:app --reload
```

Потрібні PostgreSQL і Redis.

---

## Перевірки

```bash
curl -s https://relay1.morok.app/health
systemctl is-active morok-relay morok-mail
.venv/bin/alembic current
sudo -u postgres psql morok_relay -c "SELECT hostname, is_trusted FROM federation_peers;"
journalctl -u morok-relay --since "10 min ago"
```

Федеративний пошук ходить **лише** на довірених peer'ів із
`federation_peers`. Якщо там порожньо або `is_trusted = f` —
`@user@інший.релей` не знайдеться.
