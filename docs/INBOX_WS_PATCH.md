# Patch для api/inbox.py: ліміт одночасних WS-з'єднань

Цей файл я не переписую повністю (я не маю його актуальної версії). Зміни мінімальні — додай їх вручну у `morok_relay/api/inbox.py`.

## Що додати

### 1. Import

Десь біля інших import'ів додай:

```python
import uuid
from ..config import get_settings
from ..rate_limit import reserve_ws_slot, release_ws_slot
```

### 2. У функції що обробляє WebSocket (зазвичай `websocket_inbox` або `inbox`)

Зараз функція приблизно така:

```python
@router.websocket("/inbox")
async def websocket_inbox(
    websocket: WebSocket,
    token: str,
    redis: ...,
):
    # ... verify token, get pubkey_hex ...
    await websocket.accept()
    try:
        # ... main loop ...
    finally:
        # ... cleanup ...
```

Заміни її на цей паттерн (зберігши свою внутрішню логіку):

```python
@router.websocket("/inbox")
async def websocket_inbox(
    websocket: WebSocket,
    token: str,
    redis: ...,
):
    settings = get_settings()

    # ... verify token first, get pubkey_hex (без змін) ...
    # Якщо token недійсний — close(4001) і return, як було раніше

    # NEW: спробувати зарезервувати слот ПЕРЕД accept
    connection_id = str(uuid.uuid4())
    slot_ok = await reserve_ws_slot(
        redis,
        session.pubkey_hex,  # або як зараз називаєш змінну
        connection_id,
        settings.rate_limit_ws_connections_per_pubkey,
    )
    if not slot_ok:
        await websocket.close(code=1008, reason="too_many_concurrent_connections")
        return

    await websocket.accept()
    try:
        # ... тут вся існуюча логіка main loop без змін ...
        pass
    finally:
        # NEW: release слот в finally
        await release_ws_slot(redis, session.pubkey_hex, connection_id)
        # ... існуючий cleanup (без змін) ...
```

## Що це робить

- Ліміт **5 одночасних WS-з'єднань на pubkey** (конфігуровано через `MOROK_RATE_LIMIT_WS_CONNECTIONS_PER_PUBKEY`)
- При спробі 6-го з'єднання — close з кодом `1008` (Policy Violation) і причиною `too_many_concurrent_connections`
- Слот звільнюється навіть якщо main loop впав з виключенням (через `finally`)
- Якщо Redis впав — пускаємо (fail-open), як і HTTP rate limit

## Перевірити що працює

Після деплою спробуй з одного pubkey відкрити **6 паралельних WebSocket-з'єднань** — 6-те має закритися з кодом 1008.

Можна швидко перевірити через Python:

```python
import asyncio, websockets, json

async def open_ws(token, n):
    try:
        ws = await websockets.connect(f"wss://relay1.morok.app/ws/v1/inbox?token={token}")
        print(f"  conn {n}: opened")
        await asyncio.sleep(10)
        await ws.close()
    except Exception as e:
        print(f"  conn {n}: rejected -- {e}")

async def main():
    token = "..."  # дійсний session token
    await asyncio.gather(*[open_ws(token, i) for i in range(7)])

asyncio.run(main())
```

Очікую: перші 5 — opened, 6-та і 7-ма — rejected з 1008.
