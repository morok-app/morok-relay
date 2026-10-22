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
Для дій зі списку MOROK_ACTION_PROOF_REQUIRED підпис ОБОВ'ЯЗКОВИЙ
(без нього — 401 action_proof_required). Для решти — опціональний:
якщо переданий, перевіряється fail-closed; якщо ні — bearer-only.

`target` прив'язує підпис до КОНКРЕТНОГО об'єкта дії (self pubkey для
account/backup-дій, dms_id для скасування DMS) — без цього підпис на
одну дію міг би бути переграний для іншої дії того самого типу.
`nonce` — anti-replay: без нього той самий валідний підпис можна було
б повторно пред'явити в межах вікна свіжості.
"""
from __future__ import annotations

import time

from fastapi import HTTPException, status

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

    Fail-closed скрізь, включно з anti-replay-шаром (жорсткий свіжий
    прохід — GPT-перегляд другого раунду). РАНІШЕ Redis-збій ТУТ
    означав fail-OPEN (return True) — обґрунтування було "втрата
    доступності гірша за теоретичний ризик повтору", АЛЕ для
    account_delete/backup_replace/backup_delete/dms_cancel
    correctness важливіша за availability: коли SensitiveActionProof
    стане обов'язковим, "Redis лежить → пропускаємо replay-захист"
    означало б, що криптографічно валідний, але ПОВТОРЕНИЙ підпис
    проходить якраз у момент деградації Redis — найгірший можливий
    час для цього. Redis лежить → операція просто не пройде (503-
    подібна відмова), а не тиха деградація безпеки.
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
        # Fail-CLOSED (жорсткий свіжий прохід): Redis-збій у anti-replay-
        # шарі більше не означає "пропускаємо перевірку" — для незворотних
        # дій correctness важливіша за availability.
        return False
    return bool(claimed)


async def enforce_sensitive_action(
    redis,
    *,
    action: str,
    pubkey_hex: str,
    target: str,
    proof,
) -> None:
    """
    Єдина точка застосування для ендпоінтів. `proof` — будь-який об'єкт
    з полями action_signature_hex / action_nonce / action_timestamp
    (SensitiveActionProof або тіло, що його успадковує) або None.

      • proof є → перевірка fail-closed (401 invalid_action_proof);
      • proof нема, а дія в action_proof_required → 401 action_proof_required;
      • proof нема й дія необов'язкова → legacy bearer-only, нічого не робимо.

    Викликати ДО будь-якої мутації.
    """
    from .config import get_settings

    settings = get_settings()
    sig = getattr(proof, "action_signature_hex", None) if proof is not None else None
    if sig is None:
        if action in settings.action_proof_required_set():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="action_proof_required",
            )
        return
    valid = await verify_sensitive_action(
        redis,
        action=action,
        pubkey_hex=pubkey_hex,
        target=target,
        nonce=getattr(proof, "action_nonce", None) or "",
        timestamp=getattr(proof, "action_timestamp", None) or 0,
        signature_hex=sig,
        relay_name=settings.relay_name,
    )
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_action_proof",
        )
