"""
SensitiveActionProof — крипто-підтвердження для незворотних дій
(аудит зовн. №5, P1).

ЧОМУ ЦЕ ІСНУЄ. Bearer-токен доводить лише "хтось колись пройшов auth і
отримав сесію" — не "власник приватного ключа підтверджує САМЕ ЦЮ дію
ЗАРАЗ". Для звичайних повідомлень підміна неможлива: messages.py
окремо перевіряє Ed25519-підпис самого повідомлення. Але для
account_delete, backup replace/delete і dms_cancel довше не було
нічого, крім bearer, — вкрадений токен (навіть у межах нашої 30-денної
абсолютної стелі сесій) мав стільки ж влади над незворотними діями,
скільки й законний власник ключа.

Домен-розділений Ed25519 підпис над
(action, relay, timestamp, nonce, target) — той самий підхід, що вже
працює для DMS signed check-in (dms.py) і read receipt (messages.py).
Опціональний і зворотно-сумісний: клієнт, який ще не вміє підписувати,
проходить bearer-only шляхом, як і раніше — коли клієнти дозріють,
підпис для цих конкретних дій можна буде зробити обов'язковим.

`target` прив'язує підпис до КОНКРЕТНОГО об'єкта дії (self pubkey для
account/backup-дій, dms_id для скасування DMS) — без цього підпис на
одну дію міг би бути переграний для іншої дії того самого типу.
`nonce` — anti-replay: без нього той самий валідний підпис можна було
б повторно пред'явити в межах вікна свіжості.
"""
from __future__ import annotations

import time

from . import crypto

ACTION_SIG_WINDOW_SECONDS = 300


async def verify_sensitive_action(
    redis,
    *,
    action: str,
    pubkey_hex: str,
    target: str,
    nonce: str,
    timestamp: int,
    signature_hex: str,
    relay_name: str,
) -> bool:
    """
    Перевіряє підпис і одноразовість nonce. pubkey_hex тут — ЗАВЖДИ
    current.pubkey_hex з верифікованої сесії виклику, ніколи з тіла
    запиту: підмінити "хто підписав" через тіло неможливо.

    Fail-closed на невалідний підпис/протухле вікно; fail-OPEN на
    збій самого Redis (anti-replay-шар) — втрата доступності гірша за
    теоретичний ризик повтору в межах короткого вікна.
    """
    now = int(time.time())
    if abs(now - timestamp) > ACTION_SIG_WINDOW_SECONDS:
        return False

    message = crypto.canonical_json({
        "morok_sensitive_action": "v1",
        "action": action,
        "relay": relay_name,
        "timestamp": timestamp,
        "nonce": nonce,
        "target": target,
    })
    try:
        sig_bytes = bytes.fromhex(signature_hex)
        pubkey_bytes = bytes.fromhex(pubkey_hex)
    except ValueError:
        return False
    if not crypto.ed25519_verify(message, sig_bytes, pubkey_bytes):
        return False

    claim_key = f"morok:sensitive_action_nonce:{pubkey_hex}:{nonce}"
    try:
        claimed = await redis.set(
            claim_key, b"1", nx=True, ex=ACTION_SIG_WINDOW_SECONDS,
        )
    except Exception:
        return True  # Redis-збій у anti-replay-шарі — не блокуємо легітимну дію
    return bool(claimed)
