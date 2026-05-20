# Morok v0.9 — Federation Delivery Deploy Guide

Цей пакет робить федерацію реально працюючою. До цього handshake був, але повідомлення не routing'ились на інший relay. Тепер:

- Lookup між relay'ями з кешуванням (`?relay=` параметр)
- send_envelope автоматично розпізнає local vs federation
- Durable outbound queue в Postgres з retry/backoff
- Background worker як systemd timer (1 хв)

---

## Що в архіві

**Нові файли (4):**
- `alembic/versions/005_federation_outbound_queue.py`
- `morok_relay/scripts/federation_worker.py`
- `deploy/morok-federation-worker.service`
- `deploy/morok-federation-worker.timer`
- `tests/test_federation_worker.py` (7 тестів, всі pass)

**Patch existing (3 — повний файл):**
- `morok_relay/models.py` — додано `FedQueueStatus` enum + `FederationOutboundQueue` model
- `morok_relay/api/users.py` — `lookup` з `?relay=` federation fallback
- `morok_relay/api/messages.py` — `send_envelope` routing local/federation

**Без змін:**
- federation.py, federation_client.py, queue.py, dms.py, groups.py, auth.py — нічого не торкаю

---

## Локально (твій ПК)

1. Розпакуй ZIP
2. Скопіюй файли в твій локальний `morok-relay/`:
   - 4 нові файли (зі своїми шляхами)
   - 3 patch файли (замінити існуючі)
3. **Локально перевір синтаксис:**
   ```
   python -m py_compile morok_relay/models.py
   python -m py_compile morok_relay/api/users.py
   python -m py_compile morok_relay/api/messages.py
   python -m py_compile morok_relay/scripts/federation_worker.py
   ```
   Має бути тиша. Якщо щось — скажи.
4. GitHub Desktop: 7 changes
5. Commit: `federation delivery v0.9 — durable outbound queue with retry`
6. Push origin

---

## На сервері — обидва relay паралельно

**Важливо:** деплой однаковий на relay1 і relay2. Обидва мають мати міграцію і worker.

### Спочатку relay1 (Hetzner)

```bash
ssh morok@62.238.28.107
cd ~/morok-relay
git pull
source .venv/bin/activate

# Міграція
alembic upgrade head
# Очікую: Running upgrade 004_dead_man_switch -> 005_federation_outbound

# Вихід з venv/morok у root
exit

# Як root — деплой systemd timer
sudo cp /home/morok/morok-relay/deploy/morok-federation-worker.service /etc/systemd/system/
sudo cp /home/morok/morok-relay/deploy/morok-federation-worker.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now morok-federation-worker.timer

# Перезапустити сам relay (новий код у messages.py / users.py)
sudo systemctl restart morok-relay

# Перевірка
sleep 3
sudo systemctl status morok-relay --no-pager | head -5
sudo systemctl list-timers --no-pager | grep federation
curl -s https://relay1.morok.app/health
```

Очікую:
- relay active running
- timer показує `morok-federation-worker.timer` з next run в межах 60s
- health повертає JSON з version 0.8.0

### Потім relay2 (Contabo)

Те саме на 167.86.120.176:

```bash
ssh morok@167.86.120.176
cd ~/morok-relay
git pull
source .venv/bin/activate
alembic upgrade head
exit

sudo cp /home/morok/morok-relay/deploy/morok-federation-worker.service /etc/systemd/system/
sudo cp /home/morok/morok-relay/deploy/morok-federation-worker.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now morok-federation-worker.timer
sudo systemctl restart morok-relay

sleep 3
sudo systemctl status morok-relay --no-pager | head -5
sudo systemctl list-timers --no-pager | grep federation
curl -s https://relay2.morok.app/health
```

---

## Перевірка що federation реально працює

Це **manual e2e тест**. Заходимо на relay1, готуємо клієнта що шле повідомлення юзеру на relay2.

### Підготовка test users

На **relay2**, створимо тестового юзера через client_simulator (він робить auth + claim_username):

```bash
ssh morok@167.86.120.176
cd ~/morok-relay
source .venv/bin/activate
# Запускаємо client_simulator з конкретним username — він зробить auth+claim
python tools/client_simulator.py --relay https://relay2.morok.app
# (Якщо simulator не приймає прапор — просто запусти. Він створить юзера на цьому relay.)
```

Запам'ятай pubkey з виводу (там буде `Authenticated as: <hex>`).

### Тест federation lookup з relay1

```bash
ssh morok@62.238.28.107
# Як relay1 спробуй lookup юзера що тільки що зареєстрований на relay2
curl -s "https://relay1.morok.app/api/v1/users/lookup/testuser?relay=relay2.morok.app"
```

Очікую: `{"pubkey_hex":"...","username":"testuser","home_relay":"relay2.morok.app","last_seen_at":null}`

Якщо отримав 404 — або юзер не створений на relay2, або federation lookup впав. Дивимось `journalctl -u morok-relay -n 30`.

### Перевірка queue

Після того як relay1 знає юзера на relay2, він готовий routing'ити. Щоб реально тестувати — потрібен клієнт що відправляє envelope. client_simulator зараз не підтримує federation flow з коробки, тому тест простіший: вручну вставимо запис у queue і подивимось чи worker його доставить.

На relay1, як root:

```bash
sudo -u postgres psql -d morok_relay
```

В psql:

```sql
-- Подивитись чи таблиця створена
\d federation_outbound_queue

-- Подивитись чи юзер з relay2 справді закешований
SELECT username, home_relay FROM users WHERE home_relay = 'relay2.morok.app';
```

Має бути запис тестового юзера. Якщо так — lookup і кешування працюють.

### Resilience тест — основний доказ

Це **симуляція даун-тайму relay2**:

1. На relay2: `sudo systemctl stop morok-relay`
2. На relay1 — створи envelope через client_simulator (або curl). Він заїде в `federation_outbound_queue` зі статусом `pending`.
3. Через 60s worker спробує forward → relay2 не відповідає → запис йде в `attempts=1`, `next_attempt_at = now + 30s`, `last_error = ...`.
4. Подивитись через psql на relay1:
   ```sql
   SELECT envelope_id, target_relay, status, attempts, last_error
   FROM federation_outbound_queue
   ORDER BY created_at DESC LIMIT 5;
   ```
5. Через 2-3 хвилини на relay2: `sudo systemctl start morok-relay`
6. Чекаємо наступний tick worker'а на relay1 (до 60s)
7. Перевіряємо знову:
   ```sql
   SELECT envelope_id, status, delivered_at FROM federation_outbound_queue ...
   ```
   Очікую: `status='succeeded'`, `delivered_at` ≠ null

Якщо це працює — **federation реально доставляє через downtime**.

---

## Що дивитись у логах

```bash
# Worker логи (на relay1 чи relay2)
sudo journalctl -u morok-federation-worker --no-pager -n 50

# Сам relay логи
sudo journalctl -u morok-relay --no-pager -n 50 | grep -i federation
```

Worker пише такі рядки:

```
INFO morok_relay.scripts.federation_worker: Federation worker run: recovered=0 processed=1 succeeded=1 failed=0
INFO morok_relay.scripts.federation_worker: Delivered envelope abc123... to relay2.morok.app
INFO morok_relay.scripts.federation_worker: Retrying envelope abc123... to relay2.morok.app in 30s (attempt 1/11)
ERROR morok_relay.scripts.federation_worker: Dead-lettered envelope abc123... to relay2.morok.app after 11 attempts: ...
```

---

## Rollback

Якщо щось не так — на сервері:

```bash
sudo systemctl stop morok-federation-worker.timer
sudo systemctl restart morok-relay   # без новогo коду треба git revert + pull
```

Міграція даних не псує — `005` тільки додає таблицю. Можна жити з нею без worker'а, або зробити `alembic downgrade -1` щоб видалити таблицю.

---

## Що НЕ робимо в v0.9

- Onion для relay2 (наступний день)
- Monitoring (relay1 не алертить якщо relay2 впав)
- Повернення відправнику `delivery_failed` коли dead_letter
- Federation для груп і DMS (поки що тільки 1-on-1)

Це все на майбутні ітерації. Зараз — фундамент готовий.
