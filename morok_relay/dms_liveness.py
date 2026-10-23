"""
dms_liveness.py — хто з власників DMS уже вміє підписаний check-in.

Режим «лише підписаний check-in» (dms_checkin у MOROK_ACTION_PROOF_REQUIRED)
вимикає «я живий» через звичайний bearer-токен. Але старі клієнти (Android
до 1.2.0, Windows/веб до 0.9.4) явного check-in не роблять узагалі — для
них єдиний сигнал живості саме bearer-активність. Вимкнути її всім одразу
означало б, що «мертва рука» спрацює проти волі власника старого клієнта.

Тому суворий режим діє ПЕРСОНАЛЬНО: лише для того, хто хоч раз зробив
валідний підписаний check-in (його клієнт це вміє). Для решти лишається
стара поведінка. Злодій із токеном позначку не поставить — потрібен ключ.
Втрата Redis = позначки зникли = повернення до старої (безпечної для
власника) поведінки до наступного підписаного check-in.
"""
from __future__ import annotations

import logging

from .config import get_settings

logger = logging.getLogger(__name__)

_KEY = "morok:dms:signed_checkin:{}"
# поновлюється кожним підписаним check-in; рік без жодного — повертаємось
# до старої поведінки
_TTL_SECONDS = 400 * 86400


async def remember_signed_checkin(redis, pubkey_hex: str) -> None:
    try:
        await redis.set(_KEY.format(pubkey_hex), b"1", ex=_TTL_SECONDS)
    except Exception as e:  # noqa: BLE001
        logger.warning("signed check-in marker write failed: %s", e)


async def signed_checkin_enforced(redis, pubkey_hex: str) -> bool:
    """True — bearer більше не підтверджує живість цього власника."""
    if "dms_checkin" not in get_settings().action_proof_required_set():
        return False
    try:
        return bool(await redis.exists(_KEY.format(pubkey_hex)))
    except Exception:  # noqa: BLE001
        return False
