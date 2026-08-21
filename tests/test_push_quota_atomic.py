"""
Push subscription quota — справжня атомарність (жорсткий свіжий прохід
— знахідка, вже вказана попереднім зовнішнім аудитом №5: "Web Push
quota зроблена через COUNT → INSERT, тому під сильною concurrency
сама межа 10 теж не строго атомарна". Раніше виправлено лише FCM-
паритет із web push (обидва мали ту саму неатомарну проблему разом);
атомарність саму по собі не було закрито.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from morok_relay.api.push import MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT

pytestmark = pytest.mark.asyncio

OWNER = "aa" * 32


async def test_concurrent_web_push_subscribe_never_exceeds_quota(
    pg_sessionmaker, redis, monkeypatch,
):
    """
    ГОЛОВНИЙ ТЕСТ. Квота майже вичерпана (MAX-1), п'ять паралельних
    subscribe на РІЗНІ endpoints (щоб не потрапити в "existing"-гілку)
    на останнє вільне місце — атомарно (advisory lock) має пройти
    рівно один.

    Barrier синхронізує ПІСЛЯ rate-limit перевірки (яка сама по собі
    10/хв — забагато паралельних задач впало б на rate-limit раніше,
    ніж дійшло б до критичної секції) і ПЕРЕД advisory lock/count-
    check — без цього швидкий локальний Postgres міг би виконати
    задачі настільки послідовно, що вони просто не перетнуться в
    критичній секції (той самий урок, що вже був із group capacity
    race).
    """
    import morok_relay.api.push as push_mod
    from morok_relay import db as db_module
    from morok_relay.api.push import PushKeys, PushSubscribeRequest
    from morok_relay.config import get_settings
    from morok_relay.models import PushSubscription
    from morok_relay.sessions import Session

    monkeypatch.setattr(db_module, "_session_factory", pg_sessionmaker)
    monkeypatch.setattr(get_settings(), "vapid_public_key_b64", "dGVzdA==")

    now = int(time.time())
    async with pg_sessionmaker() as setup_db:
        for i in range(MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT - 1):
            setup_db.add(PushSubscription(
                pubkey=bytes.fromhex(OWNER),
                endpoint=f"https://fcm.googleapis.com/fcm/send/pre-subscription-{i}",
                p256dh="a" * 20, auth="b" * 20,
                created_at=now, updated_at=now,
            ))
        await setup_db.commit()

    session = Session(token="t" * 64, pubkey_hex=OWNER, expires_at=2**31)
    n = 5
    barrier = asyncio.Barrier(n)

    # ВАЖЛИВИЙ ІНСАЙТ (знайдено методом проб): barrier НЕ МОЖНА ставити
    # ВСЕРЕДИНІ (чи одразу після входу в) критичну секцію, яку advisory
    # lock захищає — lock ФІЗИЧНО не пускає 5 транзакцій туди одночасно
    # (у цьому й сенс механізму), тож barrier там ніколи не набере 5
    # учасників і висне САМЕ ТОМУ, ЩО ФІКС ПРАЦЮЄ ПРАВИЛЬНО. Правильна
    # точка — ПЕРЕД усім post_subscribe (тобто ПЕРЕД advisory lock
    # взагалі, на першому await у функції — rate-limit): спільна для
    # обох версій коду, не залежить від того, фікс це чи regression.
    # Без штучного sleep — Python asyncio виконує "готові" корутини в
    # одному tick послідовно без затримок між ними, тож 5 задач, що всі
    # прокинулись в ОДНОМУ tick, продовжують до наступного await
    # (advisory lock/count-check) настільки близько одна до одної,
    # наскільки asyncio-семантика взагалі дозволяє без реального
    # багатопоточного паралелізму.
    real_check_rate_limit = push_mod.check_rate_limit
    real_count = push_mod._count_push_subscriptions

    async def synced_rate_limit(*a, **kw):
        result = await real_check_rate_limit(*a, **kw)
        await barrier.wait()
        return result

    # ЧЕСНА ПРИМІТКА ПРО МЕЖІ ЦЬОГО ТЕСТУ (знайдено методом проб):
    # справжній asyncio.Barrier(n) прямо перед count-запитом ДОВОДИТЬ
    # регресію бездоганно (перевірено окремо: rollback-версія без
    # advisory lock дає 5 успішних з 5 замість 1), АЛЕ той самий
    # barrier ВСЕРЕДИНІ delayed_count ЗАВИСАЄ (deadlock) на фікс-
    # версії — і це не баг тесту, а сама природа advisory lock: він
    # ФІЗИЧНО не пускає n транзакцій у критичну секцію одночасно (у
    # цьому й суть механізму), тож barrier там ніколи не набере n
    # учасників. Ідеальний concurrency-тест і коректний lock-based
    # фікс архітектурно несумісні в одному й тому самому тесті.
    #
    # Тому тут — м'якший sleep (не barrier): тест підтверджує, що
    # ФІКС не ламає звичайну поведінку і витримує конкурентне
    # навантаження без падінь чи deadlock. Строге regression-
    # доведення (що race реально існує без фіксу) зроблено окремо,
    # разовою перевіркою з тимчасово посиленою синхронізацією — не
    # як частина цього файлу, бо вона зависла б саме на фіксі.
    async def delayed_count(db_, pk):
        await asyncio.sleep(0.05)
        return await real_count(db_, pk)

    async def try_subscribe(i: int) -> bool:
        async with pg_sessionmaker() as own_db:
            try:
                await push_mod.post_subscribe(
                    PushSubscribeRequest(
                        endpoint=f"https://fcm.googleapis.com/fcm/send/new-subscription-{i}",
                        keys=PushKeys(p256dh="a" * 20, auth="b" * 20),
                    ),
                    session, own_db, redis,
                )
                await own_db.commit()
                return True
            except Exception:
                await own_db.rollback()
                return False

    push_mod.check_rate_limit = synced_rate_limit
    push_mod._count_push_subscriptions = delayed_count
    try:
        results = await asyncio.gather(*[try_subscribe(i) for i in range(n)])
    finally:
        push_mod.check_rate_limit = real_check_rate_limit
        push_mod._count_push_subscriptions = real_count

    accepted = sum(results)
    assert accepted == 1, \
        f"прийнято {accepted} нових підписок замість рівно 1 — quota race"

    from sqlalchemy import func, select
    async with pg_sessionmaker() as check_db:
        count = (await check_db.execute(
            select(func.count()).select_from(PushSubscription)
            .where(PushSubscription.pubkey == bytes.fromhex(OWNER))
        )).scalar_one()
    assert count == MAX_PUSH_SUBSCRIPTIONS_PER_ACCOUNT


async def test_subscribe_still_works_normally(db, redis, monkeypatch):
    """Контроль: звичайний одиночний subscribe не зламаний advisory lock."""
    from morok_relay.api.push import PushKeys, PushSubscribeRequest, post_subscribe
    from morok_relay.config import get_settings
    from morok_relay.sessions import Session

    monkeypatch.setattr(get_settings(), "vapid_public_key_b64", "dGVzdA==")
    session = Session(token="t" * 64, pubkey_hex="bb" * 32, expires_at=2**31)
    result = await post_subscribe(
        PushSubscribeRequest(
            endpoint="https://fcm.googleapis.com/fcm/send/single-subscription",
            keys=PushKeys(p256dh="a" * 20, auth="b" * 20),
        ),
        session, db, redis,
    )
    assert result["ok"] is True
