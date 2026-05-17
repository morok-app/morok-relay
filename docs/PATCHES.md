# v0.9 patches: підключення rate-limit до існуючих endpoint'ів

Це **тільки додавання** імпорту і `dependencies=[...]` до існуючих роутів.
Жодна логіка endpoint'ів не змінюється. Я НЕ переписую повні файли — щоб
випадково не зламати щось специфічне у твоїй версії (минулого разу так
сталося з `create_session_token` vs `create_session`).

Зміни мінімальні: 4 файли, кожен — додати 1 import + 1-2 dependency.

---

## 1. `morok_relay/api/auth.py`

### Додати import (десь біля інших `from ..` import'ів):

```python
from fastapi import Depends
from ..config import get_settings
from ..rate_limit import rate_limit_by_ip
```

Якщо `Depends` уже імпортується з `fastapi` — додай тільки `Depends` до існуючого рядка. Якщо `get_settings` уже імпортується — лиши як є.

### Знайди декоратор для challenge endpoint:

```python
@router.post("/challenge", ...)
async def request_challenge(...):
```

Додай у параметри декоратора **новий рядок з dependencies**:

```python
@router.post(
    "/challenge",
    response_model=ChallengeResponse,   # ← залиши що було
    # ... інші параметри декоратора без змін ...
    dependencies=[Depends(rate_limit_by_ip(
        "auth_challenge",
        get_settings().rate_limit_auth_per_minute,
    ))],
)
async def request_challenge(...):
```

### Те ж саме для verify endpoint:

```python
@router.post(
    "/verify",
    # ... залиш що було ...
    dependencies=[Depends(rate_limit_by_ip(
        "auth_verify",
        get_settings().rate_limit_auth_per_minute,
    ))],
)
async def verify_challenge(...):
```

### НЕ чіпати: `/session`, `/session/revoke-all` — там auth уже є, ці не лімітуємо.

---

## 2. `morok_relay/api/messages.py`

### Додати import:

```python
from fastapi import Depends
from ..config import get_settings
from ..rate_limit import rate_limit_by_pubkey
```

### Знайди декоратор для POST root:

```python
@router.post("", ...)
async def send_envelope(...):
```

Додай dependency:

```python
@router.post(
    "",
    # ... залиш що було ...
    dependencies=[Depends(rate_limit_by_pubkey(
        "messages_send",
        get_settings().rate_limit_messages_per_minute,
    ))],
)
async def send_envelope(...):
```

### НЕ чіпати: GET /messages, GET /messages/{id}, DELETE /messages/{id}

---

## 3. `morok_relay/api/groups.py`

### Додати import:

```python
from fastapi import Depends
from ..config import get_settings
from ..rate_limit import rate_limit_by_pubkey
```

### Декоратор `POST ""` (create_group):

```python
@router.post(
    "",
    # ... залиш що було ...
    dependencies=[Depends(rate_limit_by_pubkey(
        "groups_create",
        get_settings().rate_limit_group_create_per_minute,
    ))],
)
async def create_group(...):
```

### Декоратор `POST "/{group_id}/messages"` (send_group_message):

```python
@router.post(
    "/{group_id}/messages",
    # ... залиш що було ...
    dependencies=[Depends(rate_limit_by_pubkey(
        "groups_message",
        get_settings().rate_limit_group_messages_per_minute,
    ))],
)
async def send_group_message(...):
```

### НЕ чіпати: всі GET / DELETE / `POST /{id}/members`

---

## 4. `morok_relay/api/dms.py`

### Додати import:

```python
from fastapi import Depends
from ..config import get_settings
from ..rate_limit import rate_limit_by_pubkey
```

### Декоратор `POST ""` (create_dms):

```python
@router.post(
    "",
    # ... залиш що було ...
    dependencies=[Depends(rate_limit_by_pubkey(
        "dms_create",
        get_settings().rate_limit_dms_create_per_minute,
    ))],
)
async def create_dms(...):
```

### НЕ чіпати: GET, check-in, cancel

---

## 5. `morok_relay/api/inbox.py` (WebSocket)

Дивись окремий файл `docs/INBOX_WS_PATCH.md` — там 3 рядки додати у функцію WS.

Якщо вирішиш зробити це **пізніше**, нічого не зламається — HTTP rate limits
працюватимуть, тільки WS не буде обмежений по concurrent connections.

---

## Підсумок

| Файл | Що додати | Скільки рядків |
|---|---|---|
| `api/auth.py` | 3 import-и + 2 dependencies | ~8 |
| `api/messages.py` | 3 import-и + 1 dependency | ~6 |
| `api/groups.py` | 3 import-и + 2 dependencies | ~9 |
| `api/dms.py` | 3 import-и + 1 dependency | ~6 |
| `api/inbox.py` | (опціонально) | ~6 |

Це разом ~35 рядків змін у 5 файлах. Решта файлів — НЕ чіпати.

## Перевірка перед коммітом

Після всіх правок, **локально** на ПК зроби:

```bash
cd C:\Users\1\Desktop\morok-relay
python -m py_compile morok_relay/api/auth.py
python -m py_compile morok_relay/api/messages.py
python -m py_compile morok_relay/api/groups.py
python -m py_compile morok_relay/api/dms.py
```

Має бути тиша (без помилок). Якщо є SyntaxError — там видно номер рядка,
скидай і виправлю.
