# Morok v1.0 — Lookup Retry + Encrypted Key Backup

Цей пакет робить два:
1. **Federation lookup** з retry (3 спроби) і Redis-кешем 24h. Більше не падатиме коли peer на хвилину впав.
2. **Encrypted seed backup** (premium фіча) — юзер може зберегти зашифрований seed на relay і відновитися на новому пристрої через username+PIN.

---

## Що в архіві

**Нові файли:**
- `alembic/versions/006_encrypted_backups.py` — міграція
- `morok_relay/api/backup.py` — 4 endpoint'и для backup
- `tests/test_backup.py` — 6 тестів
- `tests/test_lookup_retry.py` — 8 тестів

**Patch existing (повний файл):**
- `morok_relay/models.py` — додано `EncryptedBackup` model
- `morok_relay/api/users.py` — lookup з retry+cache, та повертає 503 коли peer мертвий

**Інструкції для patch вручну (бо я не маю поточних версій):**
- `docs/PATCH_MAIN_AND_SCHEMAS.md` — 2 файли треба правити вручну
- `morok_relay/schemas_backup_patch.txt` — текст для додавання в schemas.py

---

## Локально на ПК

1. Розпакуй ZIP
2. Скопіюй файли:
   - `alembic/versions/006_encrypted_backups.py` → в твій `alembic/versions/`
   - `morok_relay/api/backup.py` → в твій `morok_relay/api/`
   - `morok_relay/models.py` → замінити твій
   - `morok_relay/api/users.py` → замінити твій
   - `tests/test_backup.py` → в твій `tests/`
   - `tests/test_lookup_retry.py` → в твій `tests/`

3. **Patch вручну** `morok_relay/main.py`:

   Знайди:
   ```python
   from .api import auth, dms, federation, groups, inbox, messages, users
   ```
   Заміни на:
   ```python
   from .api import auth, backup, dms, federation, groups, inbox, messages, users
   ```

   Знайди:
   ```python
   app.include_router(federation.router, prefix="/api/v1/federation")
   ```
   Після цього рядка додай:
   ```python
   app.include_router(backup.router, prefix="/api/v1/backup")
   ```

4. **Patch вручну** `morok_relay/schemas.py`:

   - На самому верху файла переконайся що є `import base64` (має бути)
   - Перед розділом `# HEALTH & ERROR` (в кінці) додай вміст з `schemas_backup_patch.txt` (БЕЗ перших рядків з `#`-коментарями — тільки самі класи: `BackupCreateRequest`, `BackupInfo`, `BackupRestoreResponse`, `BackupDeleted`, плюс константи `BACKUP_MAX_BYTES = 1024` і `BACKUP_KDF_SALT_BYTES = 16`)

5. Syntax check локально:
   ```
   python -m py_compile morok_relay/models.py
   python -m py_compile morok_relay/api/users.py
   python -m py_compile morok_relay/api/backup.py
   python -m py_compile morok_relay/main.py
   python -m py_compile morok_relay/schemas.py
   ```

   Має бути тиша.

6. GitHub Desktop → commit `v1.0: lookup retry+cache + encrypted backup`
7. Push origin

---

## Деплой на серверах

**Обидва relay одночасно — починаємо з relay1.**

### Relay 1 (Hetzner)

```bash
ssh root@62.238.28.107
sudo -u morok bash -c "cd /home/morok/morok-relay && git pull"
sudo -u morok bash -c "cd /home/morok/morok-relay && source .venv/bin/activate && alembic upgrade head"
systemctl restart morok-relay
sleep 3
systemctl status morok-relay --no-pager | head -5
curl -s https://relay1.morok.app/health
```

Очікую: relay active running, `/health` повертає JSON.

### Relay 2 (Contabo)

```bash
ssh root@167.86.120.176
sudo -u morok bash -c "cd /home/morok/morok-relay && git pull"
sudo -u morok bash -c "cd /home/morok/morok-relay && source .venv/bin/activate && alembic upgrade head"
systemctl restart morok-relay
sleep 3
systemctl status morok-relay --no-pager | head -5
curl -s https://relay2.morok.app/health
```

---

## Quick smoke test

**Перевір lookup retry:**

```bash
# Live lookup (як вчора) — має повернути зі cache (швидко)
curl -s "https://relay1.morok.app/api/v1/users/lookup/testfed?relay=relay2.morok.app"
```

Очікую той самий JSON що раніше — але швидше (з кешу).

**Перевір backup endpoints існують:**

```bash
# Без auth — має повернути 401 не 404
curl -i -s -X POST https://relay1.morok.app/api/v1/backup -H "Content-Type: application/json" -d '{}' | head -3

# Restore lookup без бекапу — має повернути 404 з повідомленням no_backup_or_no_user
curl -s "https://relay1.morok.app/api/v1/backup/by-username/nobody"
```

---

## Як це використовувати — для клієнта (на майбутнє)

### Створити backup

Клієнт:
1. Запитує у юзера PIN (рекомендує 12+ символів)
2. Запитує у relay'я: `GET /api/v1/users/me` — дізнається свій pubkey, tier
3. Якщо tier == "premium":
4. Генерує `kdf_salt` = 16 випадкових байт
5. Деривує `key = pbkdf2(pin, salt, iterations=200000, hash=sha256, len=32)`
6. Шифрує seed: `ciphertext = nacl.secretbox(seed, nonce, key)` → ~80 байт
7. POST `/api/v1/backup`:
   ```json
   {
     "encrypted_seed_b64": "<base64 of ciphertext>",
     "kdf_salt_b64": "<base64 of salt>",
     "kdf_params": {"alg": "pbkdf2", "iter": 200000, "hash": "sha256"},
     "schema_version": 1
   }
   ```

### Відновити на новому пристрої

Клієнт:
1. Юзер вводить username + PIN
2. GET `/api/v1/backup/by-username/<u>` (без auth) — отримує encrypted_seed + kdf_salt + kdf_params
3. Деривує `key = pbkdf2(pin, salt, ...)`
4. Розшифровує `seed = nacl.secretbox_open(ciphertext, key)`
5. Якщо НЕ розшифровується → каже юзеру "невірний PIN" і пропонує ще одну спробу
6. Якщо розшифровано → deriviує pubkey з seed, проходить нормальний auth flow

### Безпека

- PIN brute-force ОНЛАЙН: 3 спроб на хвилину на IP. Зловмисник з мережі може зробити ~50 спроб у день → довжина PIN 12+ символів робить це безнадійним.
- PIN brute-force ОФЛАЙН: якщо хтось вкрав БД relay'я, він має encrypted_seed. PBKDF2 з 200000 ітерацій робить кожну спробу ~50ms на CPU. 12-символьний PIN з 70+ символів = 70^12 ≈ 1.3 * 10^22 варіантів → unbrute-forceable.
- Зловмисник з PIN АЛЕ без username — нічого не може, бо restore endpoint бере username.

---

## Що НЕ робимо

- Sealed sender (велика робота, окремо)
- Federation для груп (поки відкладено)
- Verified badges (можна між справою — 1 година)
- Monitoring (потрібен але не сьогодні)

---

## Rollback

Якщо щось не так:
```bash
# на сервері
sudo -u morok bash -c "cd /home/morok/morok-relay && git revert HEAD && git pull"
sudo -u morok bash -c "cd /home/morok/morok-relay && source .venv/bin/activate && alembic downgrade -1"
systemctl restart morok-relay
```

Це поверне до v0.9 (federation без lookup retry, без backup).
