"""
Per-recipient message queue in Redis.

For each recipient pubkey, we maintain a sorted set of envelope_ids that
are awaiting delivery. The score is the message's hard expiry timestamp
(creation_time + ttl, capped at hard ceiling) — this lets us efficiently
prune expired entries.

We also publish on a per-recipient channel for real-time delivery via
the WebSocket inbox endpoint. As of the delete-feature pass, channel
payloads are JSON events of the form:
    {"kind": "new", "envelope_id": "..."}
    {"kind": "deleted", "envelope_id": "...", "by": "<pubkey_hex>",
     "group_id": "<uuid>"|null}

The WS reader has a backward-compat path that treats a bare envelope_id
string as a "new" event, so a half-rolled deploy doesn't drop messages.

Keys
----
    morok:inbox:{recipient_pubkey_hex}     — SORTED SET of envelope_ids
                                             score = expires_at
    morok:envelope:{envelope_id}           — JSON of envelope metadata
                                             TTL = hard ceiling

    morok:inbox:channel:{recipient_pubkey} — Redis PUB/SUB channel
                                             message = JSON event
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time

import redis.asyncio as redis_async
from fastapi import HTTPException, status

from .blob_storage import secure_delete_blob, write_blob

logger = logging.getLogger(__name__)

# Hard cap on how many envelopes may sit in one recipient's inbox queue
# at once. Anti-flood storage guard — a recipient who hasn't been online
# can accumulate at most this many pending messages; beyond it, new sends
# are refused until they drain. Generous enough never to bite normal use
# (even a chatty group over days), tight enough to bound disk/Redis per
# user. Expired envelopes are pruned before this is checked, so it only
# counts live, undelivered messages.
MAX_INBOX_QUEUE_DEPTH = 5000

# Запас понад життя найдовшого конверта в inbox'і. Ключ має пережити
# СВІЙ вміст (інакше ми втратимо ще не забрані конверти при рестарті
# клієнта), але не жити вічно — інакше volatile-ttl не має що витісняти.
INBOX_KEY_TTL_SLACK_SECONDS = 3600

# ── Атомарна prune+count+conditional-insert (аудит зовн. №4, MEDIUM) ──
#
# ЧОМУ. Раніше ZREMRANGEBYSCORE+ZCARD (перевірка) і ZADD (вставка)
# були ОКРЕМИМИ round-trip. Документація називала MAX_INBOX_QUEUE_DEPTH
# "hard physical limit", але між перевіркою і вставкою є вікно: кілька
# паралельних відправників на ОДНОГО одержувача могли всі побачити
# depth=4999<5000 і всі пройти — overshoot на кількість паралельних
# запитів. Не catastrophic (обмежений concurrency, не необмежений), але
# "hard cap" має бути дійсно hard, якщо ми так пишемо в коментарях.
#
# EVAL атомарний за визначенням (Redis виконує скрипт однопотоково) —
# єдиний надійний спосіб зробити check-and-insert одним кроком без
# WATCH/MULTI retry-loop (який тут негарно масштабується під високий
# concurrency на популярного одержувача).
_INBOX_ENQUEUE_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local envelope_id = ARGV[2]
local expires_at = tonumber(ARGV[3])
local max_depth = tonumber(ARGV[4])

redis.call('ZREMRANGEBYSCORE', key, 0, now)
local depth = redis.call('ZCARD', key)
if depth >= max_depth then
    return 0
end
redis.call('ZADD', key, expires_at, envelope_id)
return 1
"""


# Атомарний decrement+conditional-delete для pending-recipient tracking
# (жорсткий свіжий прохід — README-обіцянка негайного видалення після
# доставки). Паралельні ACK від РІЗНИХ учасників групи на той самий
# envelope_id інакше могли б обидва прочитати SCARD>0 і жоден не
# зробити фінальне видалення (той самий клас check-then-act race, що
# ми вже закривали в кількох інших місцях) — EVAL прибирає це вікно.
#
# Повертає:
#   -1 — pending-ключ не існував (legacy-конверт, поставлений у чергу
#        ДО деплою цього фіксу, без pending-tracking) — Python-бік НЕ
#        видаляє нічого негайно, залишає на волю reaper (стара,
#        безпечна поведінка), а не хибно трактує "немає SET" як "усі
#        забрали" — це і зламало б групові конверти, де інші учасники
#        реально ще чекають.
#    0 — ще лишились інші pending-одержувачі, blob чіпати не можна.
#    1 — цей ACK був останнім; pending SET і meta вже видалені атомарно
#        всередині скрипта; Python-бік викликає secure_delete_blob().
_ACK_PENDING_LUA = """
local pending_key = KEYS[1]
local meta_key = KEYS[2]
local recipient = ARGV[1]

if redis.call('EXISTS', pending_key) == 0 then
    return -1
end

redis.call('SREM', pending_key, recipient)
local remaining = redis.call('SCARD', pending_key)
if remaining == 0 then
    redis.call('DEL', pending_key)
    redis.call('DEL', meta_key)
    return 1
end
return 0
"""


class EnqueueRejected(HTTPException):
    """
    Постановку в чергу НЕ виконано, і це не дедуп.

    Раніше всі відмови поверталися як None — тим самим значенням, що й
    успішна дедуплікація. Викликачі не могли їх розрізнити: /messages
    трактував None як «ми програли гонку дедупу, повідомлення вже
    доставляється» і віддавав клієнту псевдо-успіх, а dms_reaper узагалі
    не дивився на результат і позначав заповіт доставленим. Тобто повна
    черга одержувача або збій Redis тихо губили повідомлення, а для
    «цифрового заповіту» — рвали основну гарантію продукту.

    Тепер None означає РІВНО одне: дедуп (конверт із таким id уже в
    черзі). Будь-яка інша відмова — цей виняток.

    Нащадок HTTPException навмисно: усі API-ендпоінти, що кличуть
    enqueue_envelope, автоматично віддають коректний код замість
    вдаваного успіху, без правок у кожному з них. Фонові викликачі
    (dms_reaper, mail_convert) ловлять його своїм except Exception і
    НЕ позначають доставку успішною — тобто повторять пізніше.
    """

    def __init__(self, status_code: int, reason: str):
        super().__init__(status_code=status_code, detail=reason)
        self.reason = reason


def _inbox_key(recipient_pubkey_hex: str) -> str:
    return f"morok:inbox:{recipient_pubkey_hex}"


def _envelope_meta_key(envelope_id: str) -> str:
    return f"morok:envelope:{envelope_id}"


def _pending_recipients_key(envelope_id: str) -> str:
    """
    SET одержувачів, які ще не забрали (ACK-нули) цей конверт.

    Жорсткий свіжий прохід: README обіцяє "після отримання видаляються
    і запис у черзі, і файл із шифротекстом" — але раніше ACK видаляв
    ЛИШЕ запис із inbox (zrem), а meta й blob жили до кінця свого
    повного TTL (годинами), незалежно від того, чи одержувач уже забрав
    повідомлення. Для DM (один одержувач) це означало: файл фізично
    лежить на диску ще довго ПІСЛЯ того, як його реально доставлено.

    Для DM SET міститиме рівно одного одержувача — ACK одразу спорожнює
    його. Для групи (fan-out) SET містить усіх eligible одержувачів на
    момент відправки — видалення відбувається лише після ОСТАННЬОГО
    ACK, не раніше (той самий blob на диску використовується для всіх
    копій у групі).
    """
    return f"morok:envelope_pending:{envelope_id}"


# Redis ZSET: envelope_id → expires_at, для reaper.py (MEDIUM з фрешевого
# аудиту — "reaper масштабується як повний filesystem scan"). Замість
# rglob() над усім blob_dir (O(N) traversal + N stat() + N Redis EXISTS,
# незалежно від того, скільки blob'ів реально прострочено), reaper читає
# candidates ОДНИМ ZRANGEBYSCORE — Redis сам тримає структуру sorted by
# score в пам'яті. Записується в ТОМУ САМОМУ pipeline, де вже пишеться
# meta (enqueue_envelope / enqueue_envelope_for_recipients) — жодного
# додаткового call site, на відміну від альтернативи "додати параметр
# у write_blob" (та зачепила б 9 різних місць виклику).
#
# Full filesystem-scan (rglob) лишається — але як РІДКІСНИЙ safety-net
# прохід (orphan recovery: файли, що якимось чином лишились НЕ
# заіндексованими — crash між write_blob і enqueue, чи blob'и, записані
# ДО деплою цього фіксу), не основний щогодинний механізм.
_BLOB_EXPIRY_INDEX_KEY = "morok:blob_expiry_index"


# ── Tombstone відправника ───────────────────────────────────────────────
# Живе ДОВШЕ за metadata конверта. Потрібен для sender-delete: коли meta
# вже протухла/ack-нута, релей раніше не мав проти чого авторизувати
# запит і «вірив на слово» — можна було генерувати delete-події для
# довільних envelope_id у чужі WS-канали (spam-примітив + неправильна
# межа довіри). Зберігаємо НЕ пару (from, to), а її хеш: компрометація
# Redis не розкриває графа спілкування довше, ніж живуть самі конверти.
TOMBSTONE_EXTRA_TTL_SECONDS = 7 * 86400

# Скільки живе "цей reader реально забрав цей envelope_id" запис —
# для read-receipt entitlement (жорсткий свіжий прохід, підтверджено
# зовн. аудитом як MEDIUM: "чи був цей envelope_id узагалі адресований
# саме цьому reader"). Коротше за sender-delete tombstone (не 7 діб):
# read receipt зазвичай надсилається одразу чи протягом кількох годин
# після прочитання, не тижнями; 48 год — запас на реалістичну
# затримку (клієнт офлайн кілька днів, потім шле накопичені receipts).
DELIVERY_TOMBSTONE_TTL_SECONDS = 2 * 86400


def _sender_tombstone_key(envelope_id: str) -> str:
    return f"morok:env_tomb:{envelope_id}"


def _sender_tombstone_value(sender_pubkey_hex: str, recipient_pubkey_hex: str) -> str:
    return hashlib.sha256(
        f"{sender_pubkey_hex}|{recipient_pubkey_hex}".encode("utf-8")
    ).hexdigest()


def _delivery_tombstone_key(envelope_id: str, reader_pubkey_hex: str) -> str:
    """
    "Цей reader реально ACK-нув цей envelope_id" — записується в
    acknowledge_envelope, переживає видалення meta/blob (яке тепер
    відбувається одразу на ACK, див. _ACK_PENDING_LUA). Без цього
    entitlement-перевірка read receipt мала б перевіряти "чи meta ще
    існує" — але meta для DM зникає МИТТЄВО після того самого ACK,
    тож легітимний reader, який чесно прочитав повідомлення, отримав
    би хибну відмову для власного read receipt.
    """
    return f"morok:delivered:{envelope_id}:{reader_pubkey_hex}"


async def was_delivered_to(
    redis: redis_async.Redis, envelope_id: str, reader_pubkey_hex: str,
) -> bool:
    """
    Entitlement-перевірка для read receipt (жорсткий свіжий прохід):
    чи цей envelope_id був РЕАЛЬНО адресований і ACK-нутий саме цим
    reader'ом. Без цього bearer міг би надіслати "прочитано" для
    ЧУЖОГО envelope_id, і сервер переслав би фальшиву галочку —
    не витік plaintext, але оманливий сигнал для sender'а.
    """
    return bool(await redis.exists(
        _delivery_tombstone_key(envelope_id, reader_pubkey_hex)
    ))


def _inbox_channel(recipient_pubkey_hex: str) -> str:
    return f"morok:inbox:channel:{recipient_pubkey_hex}"


def _new_event(envelope_id: str) -> str:
    # JSON now (was bare envelope_id); reader_task in inbox.py recognises
    # both legacy bare-id and tagged-event formats.
    return json.dumps({"kind": "new", "envelope_id": envelope_id})


def _deleted_event(
    envelope_id: str,
    deleted_by_pubkey_hex: str,
    group_id: str | None = None,
) -> str:
    return json.dumps({
        "kind": "deleted",
        "envelope_id": envelope_id,
        "by": deleted_by_pubkey_hex,
        "group_id": group_id,
    })


def _read_event(
    envelope_id: str,
    reader_pubkey_hex: str,
    group_id: str | None = None,
) -> str:
    return json.dumps({
        "kind": "read",
        "envelope_id": envelope_id,
        "reader": reader_pubkey_hex,
        "group_id": group_id,
    })


def _group_gone_event(group_id: str, by_pubkey_hex: str) -> str:
    return json.dumps({
        "kind": "group_gone",
        "group_id": group_id,
        "by": by_pubkey_hex,
    })


async def publish_group_gone(
    redis: redis_async.Redis,
    recipient_pubkeys_hex: list[str],
    group_id: str,
    by_pubkey_hex: str,
) -> None:
    """
    Notify group members that the group was deleted by its creator.

    Ephemeral push (like read receipts): if a member's WS is offline,
    the event is lost — but that's fine, because clients also detect
    deleted groups lazily (GET /groups/{id} -> 404 on next open).
    """
    # Одна пачка замість N послідовних publish: для великої групи це
    # був ще один N-round-trip шлях (те саме сімейство, що depth-check
    # у enqueue_envelope_for_recipients).
    event = _group_gone_event(group_id, by_pubkey_hex)
    if not recipient_pubkeys_hex:
        return
    try:
        async with redis.pipeline(transaction=False) as pipe:
            for pk in recipient_pubkeys_hex:
                pipe.publish(_inbox_channel(pk), event)
            await pipe.execute()
    except Exception as e:
        logger.warning(
            "publish_group_gone failed for %d recipients: %s",
            len(recipient_pubkeys_hex), e,
        )


async def publish_read_receipt(
    redis: redis_async.Redis,
    sender_pubkey_hex: str,
    envelope_id: str,
    reader_pubkey_hex: str,
    group_id: str | None = None,
) -> None:
    """
    Notify a sender that one of their messages was read.

    No persistent storage — this is an ephemeral push. If the sender's
    WS is offline at this moment, the event is lost; the client will
    not retroactively learn that an old message was read after coming
    back online. That's by design: read receipts are best-effort, the
    relay should not keep state about who read what.
    """
    try:
        await redis.publish(
            _inbox_channel(sender_pubkey_hex),
            _read_event(envelope_id, reader_pubkey_hex, group_id),
        )
    except Exception as e:
        logger.warning(
            "publish_read_receipt failed for sender %s: %s",
            sender_pubkey_hex[:8], e,
        )


async def enqueue_envelope(
    redis: redis_async.Redis,
    envelope_id: str,
    sender_pubkey_hex: str,
    recipient_pubkey_hex: str,
    timestamp: int,
    ttl_seconds: int,
    signature_hex: str,
    hard_ceiling_seconds: int,
    sender_username: str | None = None,
    sealed: bool = False,
    delete_key_hash: str | None = None,
    channel: str | None = None,
    mail_from: str | None = None,
    mail_origin: str | None = None,
    extra_meta: dict | None = None,
) -> int | None:
    """
    Add an envelope to the recipient's inbox queue and publish a notification.

    Sealed Sender: when `sealed=True`, `sender_pubkey_hex`/`signature_hex`
    are empty strings — sender identity lives INSIDE the encrypted blob
    and is verified by the recipient client. `delete_key_hash` (sha256
    hex) lets the anonymous sender later prove deletion rights by
    presenting the preimage — without revealing who they are.

    `sender_username` is the username of the sender AT SEND TIME — included
    in the metadata so the recipient's client can display "@bob" instead of
    a raw pubkey prefix without doing a separate lookup.

    Returns the expires_at timestamp (capped at hard ceiling) on success,
    or None if — and ONLY if — the envelope already exists in Redis
    (dedup hit). The atomic SET NX is the dedup gate — using a separate
    envelope_exists() check here would leave a TOCTOU window where two
    concurrent sends with the same envelope_id could both pass the check
    and double-deliver.

    Будь-яка інша відмова (протух, черга одержувача переповнена, Redis
    недоступний) кидає EnqueueRejected — див. коментар до класу. Ніколи
    не повертай None для цих випадків: викликач не зможе відрізнити їх
    від дедупу і повідомить про успішну доставку, якої не було.
    """
    now = int(time.time())
    requested_expires = timestamp + ttl_seconds
    ceiling = now + hard_ceiling_seconds
    expires_at = min(requested_expires, ceiling)
    ttl_until_expiry = expires_at - now
    if ttl_until_expiry <= 0:
        # Конверт протух ще до постановки в чергу. Це НЕ успіх — раніше
        # тут повертався None і відправник бачив псевдо-«доставлено».
        raise EnqueueRejected(
            status.HTTP_400_BAD_REQUEST, "envelope_already_expired",
        )

    meta = {
        "envelope_id": envelope_id,
        "from": sender_pubkey_hex,
        "from_username": sender_username,
        "to": recipient_pubkey_hex,
        "ts": timestamp,
        "ttl": ttl_seconds,
        "sig": signature_hex,
        "expires_at": expires_at,
    }
    if sealed:
        meta["sealed"] = True
        if delete_key_hash:
            meta["delete_key_hash"] = delete_key_hash
    # channel="mail" → клієнт розшифровує через mailOpen, а не sealedDecrypt
    if channel:
        meta["channel"] = channel
    # Пошта: origin і перевірений відправник — ставить ТІЛЬКИ сервер,
    # клієнт отримувача довіряє цьому, а не полю from усередині блоба.
    if mail_origin:
        meta["mail_origin"] = mail_origin
    if mail_from:
        meta["mail_from"] = mail_from

    # extra_meta — НЕПІДПИСАНІ службові поля релею, що потрапляють у
    # metadata конверта (DMS-тригер: kind/dms_creator_pubkey/dms_id +
    # окрема доменна атестація). Той самий клас, що from_username чи
    # group_id: клієнт бачить їх у відповіді, але вони НЕ входять у
    # canonical signed structure конверта (crypto.SIGNED_FIELDS —
    # рівно from/to/ts/ttl/blob), інакше перевірка підпису впаде.
    #
    # Захист від затирання: жодне extra-поле не має права перезаписати
    # канонічне чи вже виставлене сервером (from/to/ts/ttl/sig/
    # expires_at/mail_*/sealed/...). Без цього виклик із помилковим
    # extra_meta={"from": ...} тихо підмінив би відправника в metadata.
    if extra_meta:
        for k, v in extra_meta.items():
            if k in meta:
                raise ValueError(f"extra_meta may not override reserved key {k!r}")
            meta[k] = v

    # SET NX is the dedup gate — only one writer "wins" the slot.
    written = await redis.set(
        _envelope_meta_key(envelope_id),
        json.dumps(meta).encode("utf-8"),
        ex=ttl_until_expiry,
        nx=True,
    )
    if not written:
        # Already exists (a previous send / retry won the race). The
        # inbox row and notification were already published by that
        # caller — do nothing.
        return None

    # ── Атомарний prune+count+conditional-insert (замість окремих
    # zremrangebyscore/zcard/zadd — див. коментар біля _INBOX_ENQUEUE_LUA
    # вгорі файлу: розділені кроки лишали вікно, де кілька паралельних
    # відправників на ОДНОГО одержувача могли всі побачити місце під
    # лімітом і всі пройти, прострілюючи "hard limit" на N. ──
    try:
        inserted = await redis.eval(
            _INBOX_ENQUEUE_LUA,
            1,
            _inbox_key(recipient_pubkey_hex),
            now,
            envelope_id,
            expires_at,
            MAX_INBOX_QUEUE_DEPTH,
        )
    except Exception as e:
        # Redis hiccup — не fail-open в необмежене зростання. meta вже
        # записана (SET NX вище) — прибираємо її, щоб не лишити сироту.
        logger.warning("inbox atomic enqueue failed, refusing: %s", e)
        try:
            await redis.delete(_envelope_meta_key(envelope_id))
        except Exception:
            pass
        raise EnqueueRejected(
            status.HTTP_503_SERVICE_UNAVAILABLE, "queue_backend_unavailable",
        ) from e

    if not inserted:
        # Черга одержувача справді повна (перевірено атомарно, не
        # "виглядала вільною секунду тому"). Прибираємо щойно записану
        # meta — інакше вона висіла б сиротою до власного TTL.
        try:
            await redis.delete(_envelope_meta_key(envelope_id))
        except Exception:
            pass
        raise EnqueueRejected(
            status.HTTP_429_TOO_MANY_REQUESTS, "recipient_queue_full",
        )

    async with redis.pipeline(transaction=True) as pipe:
        # TTL на САМ inbox-ключ. Без нього ZSET жив вічно: елементи
        # всередині мали score=expires_at і прибирались лише при явному
        # zremrangebyscore (тобто коли одержувач наступного разу
        # з'явиться), а сам ключ у Redis лишався БЕЗ TTL. Наслідок:
        # `maxmemory-policy volatile-ttl` не могла витіснити жодного
        # inbox'а під тиском пам'яті — policy була декоративною, і Redis
        # ішов би в OOM. EXPIRE зсувається вперед з кожним новим
        # конвертом, тож живий inbox не помре передчасно, а покинутий
        # зникне сам за hard-стелею.
        pipe.expire(
            _inbox_key(recipient_pubkey_hex),
            max(ttl_until_expiry, 60) + INBOX_KEY_TTL_SLACK_SECONDS,
        )
        pipe.publish(_inbox_channel(recipient_pubkey_hex), _new_event(envelope_id))
        # Pending-recipient tracking (жорсткий свіжий прохід) — див.
        # _pending_recipients_key і _ACK_PENDING_LUA. Для DM SET містить
        # рівно ОДНОГО одержувача: ACK одразу спорожнить його, і
        # acknowledge_envelope видалить meta+blob негайно, замість
        # чекати на природний TTL.
        pipe.sadd(_pending_recipients_key(envelope_id), recipient_pubkey_hex)
        pipe.expire(_pending_recipients_key(envelope_id), ttl_until_expiry)
        # Reaper-індекс (MEDIUM, фрешевий аудит) — score=expires_at,
        # той самий момент, коли meta й так природно протухне в Redis.
        # reaper читає прострочені candidates звідси, не з диска.
        pipe.zadd(_BLOB_EXPIRY_INDEX_KEY, {envelope_id: expires_at})
        # Tombstone для майбутнього sender-delete: переживає meta на
        # TOMBSTONE_EXTRA_TTL_SECONDS, щоб «видалити після ack/протухання»
        # досі можна було авторизувати. Sealed не потребує — там preimage.
        if not sealed and sender_pubkey_hex:
            pipe.set(
                _sender_tombstone_key(envelope_id),
                _sender_tombstone_value(sender_pubkey_hex, recipient_pubkey_hex),
                ex=ttl_until_expiry + TOMBSTONE_EXTRA_TTL_SECONDS,
            )
        await pipe.execute()

    return expires_at


async def write_blob_then_enqueue(
    envelope_id: str,
    blob_bytes: bytes,
    **enqueue_kwargs,
) -> int | None:
    """
    write_blob() + enqueue_envelope() з очищенням при відмові
    (жорсткий свіжий прохід — знахідка з зовнішнього перегляду).

    ЧОМУ ЦЕ ІСНУЄ. У п'яти місцях кодової бази (messages.py, mail.py,
    sealed.py, burner.py, federation.py remote-DM-forward) blob
    фізично писався на диск ПЕРЕД викликом enqueue_envelope(). Якщо
    цей виклик кидав EnqueueRejected (inbox одержувача повний, чи
    Redis тимчасово недоступний) — файл лишався сиротою на диску до
    найближчого reaper-проходу: не catastrophic (максимум 256 KiB на
    конверт, 60/хв на pubkey), але це компенсація постфактум, а не
    нормальний lifecycle, і при цілеспрямованому навантаженні на
    відмову — помітний дисковий churn.

    Один спільний helper замість дублювання try/except у п'яти
    місцях: важче пропустити оновлення десь, якщо колись знадобиться
    змінити цю логіку знову.

    ВАЖЛИВО: групового fan-out (enqueue_envelope_for_recipients) це
    НЕ стосується — та функція не кидає EnqueueRejected, вона
    gracefully пропускає переповнених одержувачів і завжди повертає
    результат.
    """
    await write_blob(envelope_id, blob_bytes)
    try:
        return await enqueue_envelope(
            envelope_id=envelope_id, **enqueue_kwargs,
        )
    except EnqueueRejected:
        try:
            await secure_delete_blob(envelope_id)
        except Exception as e:
            logger.warning(
                "orphan blob cleanup failed for %s after EnqueueRejected "
                "(reaper full-scan will catch it eventually): %s",
                envelope_id[:8], e,
            )
        raise


async def enqueue_envelope_for_recipients(
    redis: redis_async.Redis,
    envelope_id: str,
    sender_pubkey_hex: str,
    recipient_pubkeys_hex: list[str],
    timestamp: int,
    ttl_seconds: int,
    signature_hex: str,
    hard_ceiling_seconds: int,
    group_id: str | None = None,
    sender_username: str | None = None,
) -> tuple[int, int]:
    """
    Fan-out: deliver the same envelope to multiple recipients.

    Used by group messages — one blob is queued in N inboxes. The same
    envelope_id is reused for all of them (each inbox row points to the
    same blob on disk).

    Returns (expires_at, recipient_count).

    The metadata is stored ONCE with a 'to' of either the group_id (if
    given) or "broadcast" otherwise. This means /messages GET returns the
    same metadata to every recipient — they all see the message addressed
    to the group, not to themselves individually. That's what we want for
    group UX.
    """
    now = int(time.time())
    requested_expires = timestamp + ttl_seconds
    ceiling = now + hard_ceiling_seconds
    expires_at = min(requested_expires, ceiling)

    # Дзеркало guard'а з enqueue_envelope (див. вище): конверт, що вже
    # протух (ts близько нижньої межі вікна ±300с і крихітний ttl), дав би
    # від'ємний EX → помилка Redis → 500 ПІСЛЯ того, як blob уже записано.
    # Повертаємо (expires_at, 0) — обидва виклики (groups.py, federation.py)
    # результат ігнорують, тож форма відповіді сумісна.
    if expires_at - now <= 0:
        return expires_at, 0

    to_value = group_id if group_id else "broadcast"

    meta = {
        "envelope_id": envelope_id,
        "from": sender_pubkey_hex,
        "from_username": sender_username,
        "to": to_value,
        "ts": timestamp,
        "ttl": ttl_seconds,
        "sig": signature_hex,
        "expires_at": expires_at,
        "group_id": group_id,
    }

    new_event = _new_event(envelope_id)
    meta_json = json.dumps(meta).encode("utf-8")
    ttl_until_expiry = expires_at - now

    # Per-recipient queue cap: prune expired then skip any recipient whose
    # inbox is already at the depth limit. Unlike the DM path we DON'T
    # refuse the whole send — other group members must still get the
    # message; only the flooded inbox is skipped.
    #
    # ВИПРАВЛЕНО (детальний аналіз relay). DM-шлях уже був атомарним
    # через _INBOX_ENQUEUE_LUA, груповий — ні: окремий pipeline читав
    # ZCARD усіх учасників, формував eligible, а ЗОВСІМ ІНШИЙ pipeline
    # пізніше робив ZADD. Між ними — вікно, у яке кілька паралельних
    # групових розсилок на СПІЛЬНОГО одержувача (учасник кількох
    # активних груп) бачили однакову глибину під лімітом і всі
    # вставлялись. Доведено емпірично на незміненому коді: cap=5,
    # 3 наявні конверти, 10 паралельних fan-out'ів → прийнято 10,
    # фінальна глибина 13. «Hard cap» перевищено в 2.6 раза.
    #
    # Тепер той самий перевірений Lua, що й у DM-шляху, для КОЖНОГО
    # одержувача — але батчовано в ОДИН round-trip, тож виграш у
    # латентності (проти старих 2×N послідовних await) зберігається.
    # meta йде першою командою тієї ж пачки: конверт має з'явитись у
    # metadata НЕ ПІЗНІШЕ, ніж у чиємусь inbox'і, інакше паралельний
    # list_inbox побачив би id у черзі без metadata і мовчки його
    # пропустив.
    eligible: list[str] = []
    atomic_ok = True
    try:
        async with redis.pipeline(transaction=False) as pipe:
            pipe.set(_envelope_meta_key(envelope_id), meta_json, ex=ttl_until_expiry)
            for recipient in recipient_pubkeys_hex:
                pipe.eval(
                    _INBOX_ENQUEUE_LUA,
                    1,
                    _inbox_key(recipient),
                    now,
                    envelope_id,
                    expires_at,
                    MAX_INBOX_QUEUE_DEPTH,
                )
            results = await pipe.execute()
    except Exception as e:
        # Fail-open, як і раніше: перевірка глибини — захист сховища, а не
        # межа безпеки. Краще доставити, ніж мовчки загубити групову
        # розсилку через блимок Redis.
        logger.warning(
            "group fan-out atomic enqueue failed (allowing all): %s", e,
        )
        atomic_ok = False

    if atomic_ok:
        # results[0] — відповідь на SET meta; далі по одному EVAL на
        # одержувача, у тому самому порядку.
        for recipient, inserted in zip(
            recipient_pubkeys_hex, results[1:], strict=True,
        ):
            if inserted:
                eligible.append(recipient)
            else:
                logger.warning(
                    "inbox full for %s — skipping in group fan-out",
                    recipient[:8],
                )
    else:
        # Redis не відповів на атомарну пачку — вставляємо безумовно,
        # включно з meta, якої в такому разі теж могло не бути.
        eligible = list(recipient_pubkeys_hex)
        async with redis.pipeline(transaction=True) as pipe:
            pipe.set(_envelope_meta_key(envelope_id), meta_json, ex=ttl_until_expiry)
            for recipient in eligible:
                pipe.zadd(_inbox_key(recipient), {envelope_id: expires_at})
            await pipe.execute()

    async with redis.pipeline(transaction=True) as pipe:
        for recipient in eligible:
            # Той самий TTL на ключ, що й у DM-шляху (див. коментар там).
            pipe.expire(
                _inbox_key(recipient),
                max(ttl_until_expiry, 60) + INBOX_KEY_TTL_SLACK_SECONDS,
            )
            pipe.publish(_inbox_channel(recipient), new_event)
        # Pending-recipient tracking (жорсткий свіжий прохід) — SET
        # містить УСІХ eligible одержувачів разом: спільний blob на
        # диску використовується для всіх копій у групі, тож видалення
        # відбувається лише після ОСТАННЬОГО ACK, не раніше. Один
        # SADD з усім списком одразу — не по одному в циклі.
        if eligible:
            pipe.sadd(_pending_recipients_key(envelope_id), *eligible)
            pipe.expire(_pending_recipients_key(envelope_id), expires_at - now)
        # Reaper-індекс (MEDIUM, фрешевий аудит) — той самий, що DM-шлях.
        pipe.zadd(_BLOB_EXPIRY_INDEX_KEY, {envelope_id: expires_at})
        await pipe.execute()

    return expires_at, len(eligible)


async def list_inbox(
    redis: redis_async.Redis,
    recipient_pubkey_hex: str,
    limit: int = 50,
) -> list[dict]:
    """
    Get pending envelope metadata for a recipient.

    Returns oldest-first. Caller usually wants to fetch blob via
    blob_storage for each envelope, then mark delivered.
    """
    now = int(time.time())

    await redis.zremrangebyscore(_inbox_key(recipient_pubkey_hex), 0, now)

    envelope_ids_raw = await redis.zrange(
        _inbox_key(recipient_pubkey_hex), 0, limit - 1
    )
    envelope_ids = [eid.decode("utf-8") for eid in envelope_ids_raw]

    if not envelope_ids:
        return []

    async with redis.pipeline(transaction=False) as pipe:
        for eid in envelope_ids:
            pipe.get(_envelope_meta_key(eid))
        metas_raw = await pipe.execute()

    out = []
    for raw in metas_raw:
        if raw is None:
            continue
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return out


async def is_envelope_in_inbox(
    redis: redis_async.Redis,
    recipient_pubkey_hex: str,
    envelope_id: str,
) -> bool:
    """
    Пряма перевірка належності: чи цей envelope_id є ЧЛЕНОМ inbox-ZSET
    цього одержувача — незалежно від того, скільки всього елементів у
    черзі (жорсткий свіжий прохід: список — тут ZSCORE — не сканування
    обмеженого вікна).

    ЧОМУ ЦЕ ОКРЕМА ФУНКЦІЯ. list_inbox(limit=200) повертає лише
    найстаріші 200 записів; get_envelope_blob() раніше перевіряв
    авторизацію через "чи цей id входить у ці перші 200" — при черзі
    понад 200 (максимум за дизайном 5000, MAX_INBOX_QUEUE_DEPTH)
    легітимний власник конверта №201+ отримував хибний 404, попри те
    що конверт реально в його черзі. ZSCORE — O(1), коректний для
    будь-якого розміру черги.
    """
    score = await redis.zscore(_inbox_key(recipient_pubkey_hex), envelope_id)
    return score is not None


async def get_envelope_meta(
    redis: redis_async.Redis,
    envelope_id: str,
) -> dict | None:
    """
    Fetch envelope metadata directly by id.

    Returns None if the envelope has expired or been deleted. Used by
    the WS reader to look up metadata for a single notification without
    re-scanning the whole inbox.
    """
    raw = await redis.get(_envelope_meta_key(envelope_id))
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


async def acknowledge_envelope(
    redis: redis_async.Redis,
    recipient_pubkey_hex: str,
    envelope_id: str,
) -> bool:
    """
    Mark envelope as delivered for THIS recipient: remove from inbox.

    ВИПРАВЛЕНО (жорсткий свіжий прохід — README-обіцянка "після
    отримання видаляються і запис у черзі, і файл із шифротекстом").
    Раніше ACK видаляв ЛИШЕ inbox-запис; meta й blob жили до кінця
    свого повного TTL (годинами) незалежно від того, чи одержувач уже
    забрав повідомлення — reaper бачив "meta ще існує" і не чіпав файл.
    Для DM (один одержувач) файл фізично лежав на диску ще довго ПІСЛЯ
    реальної доставки.

    Тепер: атомарний EVAL (_ACK_PENDING_LUA) прибирає цього одержувача
    з pending-set і, якщо він був ОСТАННІМ (для групи — усі учасники
    забрали; для DM — єдиний одержувач), видаляє meta й повертає
    сигнал видалити blob. Legacy-конверти без pending-set (поставлені
    в чергу до деплою цього фіксу) безпечно падають на стару поведінку
    — reaper як safety net, а не хибне негайне видалення.

    Видалення самого файлу — fire-and-forget: навіть якщо процес
    впаде між EVAL (уже видалила pending+meta) і фактичним unlink,
    reaper підхопить осиротілий файл (meta відсутня → "доставлений
    сирота") тим самим механізмом, що вже існував.
    """
    removed = await redis.zrem(_inbox_key(recipient_pubkey_hex), envelope_id)
    if removed <= 0:
        return False

    # Delivery tombstone для read-receipt entitlement (жорсткий свіжий
    # прохід) — записуємо НЕЗАЛЕЖНО від pending-decrement нижче: цей
    # запис має пережити видалення meta, а не залежати від того, чи
    # цей ACK був "останнім" у групі. Redis-збій тут не повинен
    # ламати сам ACK (inbox уже прибрано) — fail-soft: без tombstone
    # read receipt цього конкретного reader'а пізніше просто буде
    # відхилений як неавторизований, гірше не стає.
    try:
        await redis.set(
            _delivery_tombstone_key(envelope_id, recipient_pubkey_hex),
            b"1", ex=DELIVERY_TOMBSTONE_TTL_SECONDS,
        )
    except Exception as e:
        logger.warning(
            "delivery tombstone write failed for %s: %s", envelope_id[:8], e,
        )

    try:
        result = await redis.eval(
            _ACK_PENDING_LUA,
            2,
            _pending_recipients_key(envelope_id),
            _envelope_meta_key(envelope_id),
            recipient_pubkey_hex,
        )
    except Exception as e:
        # Redis-збій на цьому кроці не повинен ламати сам ACK (inbox
        # уже прибрано вище) — просто лишаємо meta/blob на волю reaper.
        logger.warning(
            "pending-recipient decrement failed for %s: %s",
            envelope_id[:8], e,
        )
        return True

    if result == 1:
        asyncio.create_task(_delete_blob_after_last_ack(envelope_id))

    return True


async def _delete_blob_after_last_ack(envelope_id: str) -> None:
    try:
        await secure_delete_blob(envelope_id)
    except Exception as e:
        logger.warning(
            "post-ACK blob delete failed for %s (reaper will retry): %s",
            envelope_id[:8], e,
        )


async def envelope_exists(redis: redis_async.Redis, envelope_id: str) -> bool:
    """Check if an envelope is known to this relay (for dedup)."""
    return bool(await redis.exists(_envelope_meta_key(envelope_id)))


async def delete_envelope_by_sender(
    redis: redis_async.Redis,
    envelope_id: str,
    caller_pubkey_hex: str,
    recipient_pubkey_hex: str,
) -> dict:
    """
    Sender removes their DM envelope from the recipient's inbox.

    If metadata is still in Redis we authorize via meta.from. If it has
    already expired or been acked, we authorize against the sender
    TOMBSTONE (sha256 of "from|to", written at enqueue, outlives meta by
    TOMBSTONE_EXTRA_TTL_SECONDS). No tombstone → refuse: раніше тут ми
    «вірили на слово» і публікували delete-подію для довільного
    envelope_id у чужий канал.

    The blob file is left for the reaper to clean up once no inbox row
    references it.

    Returns
    -------
    dict with keys:
        ok: bool                  — operation accepted
        deleted_from_queue: bool  — envelope row was actually present
        meta_existed: bool        — recipient had not yet acked
        error: str | None         — "not_sender" | "group_message"
                                  | "recipient_mismatch" | None
    """
    meta_raw = await redis.get(_envelope_meta_key(envelope_id))
    meta_existed = meta_raw is not None

    if meta_existed:
        try:
            meta = json.loads(meta_raw)
        except json.JSONDecodeError:
            meta = {}

        if meta.get("group_id"):
            return {
                "ok": False, "deleted_from_queue": False,
                "meta_existed": True, "error": "group_message",
            }
        if meta.get("from") != caller_pubkey_hex:
            return {
                "ok": False, "deleted_from_queue": False,
                "meta_existed": True, "error": "not_sender",
            }
        if meta.get("to") != recipient_pubkey_hex:
            return {
                "ok": False, "deleted_from_queue": False,
                "meta_existed": True, "error": "recipient_mismatch",
            }
    else:
        # Meta вже нема — перевіряємо tombstone. Хеш звіряємо в constant
        # time; відсутність tombstone означає, що конверт або ніколи не
        # існував, або видалення прийшло надто пізно — в обох випадках
        # відмовляємо БЕЗ публікації події в канал одержувача.
        tomb = await redis.get(_sender_tombstone_key(envelope_id))
        if tomb is None:
            return {
                "ok": False, "deleted_from_queue": False,
                "meta_existed": False, "error": "not_found",
            }
        tomb_str = tomb.decode("utf-8") if isinstance(tomb, bytes) else tomb
        expected = _sender_tombstone_value(caller_pubkey_hex, recipient_pubkey_hex)
        if not hmac.compare_digest(tomb_str, expected):
            return {
                "ok": False, "deleted_from_queue": False,
                "meta_existed": False, "error": "not_sender",
            }

    event_payload = _deleted_event(envelope_id, caller_pubkey_hex)

    async with redis.pipeline(transaction=True) as pipe:
        pipe.zrem(_inbox_key(recipient_pubkey_hex), envelope_id)
        pipe.delete(_envelope_meta_key(envelope_id))
        pipe.delete(_sender_tombstone_key(envelope_id))
        pipe.publish(_inbox_channel(recipient_pubkey_hex), event_payload)
        results = await pipe.execute()

    return {
        "ok": True,
        "deleted_from_queue": bool(results[0]),
        "meta_existed": meta_existed,
        "error": None,
    }


async def delete_sealed_envelope(
    redis: redis_async.Redis,
    envelope_id: str,
    delete_key_hex: str,
) -> dict:
    """
    Anonymous sender deletes their SEALED envelope by presenting the
    preimage of the delete_key_hash stored in the envelope meta.

    Unlike delete_envelope_by_sender we CANNOT fall back to trusting the
    caller when meta has expired — there is no authenticated identity to
    trust. No meta => nothing to authorize against => error.

    Returns dict: ok, deleted_from_queue, error
        error: "not_found" | "not_sealed" | "wrong_key" | None
    """
    meta_raw = await redis.get(_envelope_meta_key(envelope_id))
    if meta_raw is None:
        return {"ok": False, "deleted_from_queue": False, "error": "not_found"}
    try:
        meta = json.loads(meta_raw)
    except json.JSONDecodeError:
        return {"ok": False, "deleted_from_queue": False, "error": "not_found"}

    if not meta.get("sealed") or not meta.get("delete_key_hash"):
        return {"ok": False, "deleted_from_queue": False, "error": "not_sealed"}

    try:
        presented = hashlib.sha256(bytes.fromhex(delete_key_hex)).hexdigest()
    except ValueError:
        return {"ok": False, "deleted_from_queue": False, "error": "wrong_key"}
    if not hmac.compare_digest(presented, meta["delete_key_hash"]):
        return {"ok": False, "deleted_from_queue": False, "error": "wrong_key"}

    recipient_pubkey_hex = meta.get("to") or ""
    # deleted_by порожній — відправник анонімний навіть у delete-події.
    event_payload = _deleted_event(envelope_id, "")

    async with redis.pipeline(transaction=True) as pipe:
        pipe.zrem(_inbox_key(recipient_pubkey_hex), envelope_id)
        pipe.delete(_envelope_meta_key(envelope_id))
        pipe.publish(_inbox_channel(recipient_pubkey_hex), event_payload)
        results = await pipe.execute()

    return {
        "ok": True,
        "deleted_from_queue": bool(results[0]),
        "error": None,
    }


async def delete_envelope_for_group(
    redis: redis_async.Redis,
    envelope_id: str,
    group_id: str,
    recipient_pubkeys_hex: list[str],
    deleted_by_pubkey_hex: str,
) -> dict:
    """
    Remove a group envelope from every member's inbox and push a delete
    event onto each member's channel.

    Authorization (sender-or-admin) is enforced in the router because
    it requires a DB lookup against the group membership table.

    Returns
    -------
    dict with keys:
        deleted_from_count: int   — how many member inboxes still had it
        meta_existed: bool        — metadata was still in Redis
        broadcast_to: int         — channels we published the event on
    """
    meta_key = _envelope_meta_key(envelope_id)
    meta_existed = bool(await redis.exists(meta_key))

    event_payload = _deleted_event(
        envelope_id, deleted_by_pubkey_hex, group_id=group_id,
    )

    async with redis.pipeline(transaction=True) as pipe:
        pipe.delete(meta_key)
        for r in recipient_pubkeys_hex:
            pipe.zrem(_inbox_key(r), envelope_id)
            pipe.publish(_inbox_channel(r), event_payload)
        results = await pipe.execute()

    # Layout: [delete_meta, zrem_0, publish_0, zrem_1, publish_1, ...]
    # zrem results live at indices 1, 3, 5, ...
    deleted_from_count = sum(
        1 for i in range(1, len(results), 2) if results[i]
    )

    return {
        "deleted_from_count": deleted_from_count,
        "meta_existed": meta_existed,
        "broadcast_to": len(recipient_pubkeys_hex),
    }
