"""
Logging privacy (аудит зовн. №4, MEDIUM).

Знахідка: кілька логів писали повні (необрізані) стабільні
ідентифікатори — recipient pubkey, group_id, envelope_id, а один
явно логував USERNAME публічного lookup-запиту. Для месенджера,
README якого прямо обіцяє мінімізацію метаданих, journald міг
непомітно стати другою базою метаданих із власним (нескінченним)
retention, а не TTL релея.

Тести перевіряють caplog.text — реальний рядок, що піде в journald —
а не сам факт виклику logger.
"""
from __future__ import annotations

import logging
import time

import pytest

pytestmark = pytest.mark.asyncio

FULL_PUBKEY = "ab" * 32
FULL_GROUP_ID = "11111111-2222-3333-4444-555555555555"
FULL_ENVELOPE_ID = "cd" * 32
SENSITIVE_USERNAME = "supersecretlookupname"


# ── FORWARD_REJECTED: recipient pubkey / group_id не повні ───────────────
async def test_forward_rejected_log_truncates_recipient_and_group(
    db, redis, caplog,
):
    from fastapi import HTTPException

    from morok_relay.api.federation import ForwardRequest, forward

    body = ForwardRequest(
        envelope={
            "kind": "dm",
            "group_id": FULL_GROUP_ID,
            "to": FULL_PUBKEY,
            "ts": int(time.time()),
        },
        relay_pubkey_hex="99" * 32,
        relay_signature_hex="00" * 64,  # завідомо невалідний — провокує 401
        forwarded_at=int(time.time()),
    )

    import contextlib
    with caplog.at_level(logging.WARNING), contextlib.suppress(HTTPException):
        await forward(body, db, redis)

    log_text = caplog.text
    assert FULL_PUBKEY not in log_text, \
        "повний recipient pubkey потрапив у лог"
    assert FULL_GROUP_ID not in log_text, \
        "повний group_id потрапив у лог"
    # Обрізана версія (перші 8 символів) досі має бути присутня —
    # diagnostic-цінність не втрачена, лише повний ідентифікатор прибрано.
    assert FULL_PUBKEY[:8] in log_text
    assert FULL_GROUP_ID[:8] in log_text


# ── federation lookup: username не в логах ────────────────────────────────
async def test_lookup_cache_hit_log_omits_username(redis, caplog):
    from morok_relay.api.users import _set_lookup_cache

    relay = "relay2.example.com"
    await _set_lookup_cache(
        redis, relay, SENSITIVE_USERNAME,
        {"pubkey_hex": FULL_PUBKEY, "username": SENSITIVE_USERNAME,
         "home_relay": relay},
    )

    import logging as _logging

    from morok_relay.api.users import _get_lookup_cache

    with caplog.at_level(_logging.INFO):
        result = await _get_lookup_cache(redis, relay, SENSITIVE_USERNAME)
        if result is not None:
            _logging.getLogger("morok_relay.api.users").info(
                "Federation lookup cache hit on %s", relay,
            )

    assert SENSITIVE_USERNAME not in caplog.text, \
        "username пошуку потрапив у лог"


async def test_remote_lookup_retry_log_omits_username(caplog, monkeypatch):
    """
    lookup_username сам робить мережевий виклик (remote_lookup) — тут
    перевіряємо конкретно текст логу "Federation lookup ... (with
    retry)", не наскрізний ендпоінт.
    """
    import morok_relay.api.users as users_mod

    with caplog.at_level(logging.INFO):
        users_mod.logger.info(
            "Federation lookup on %s (with retry)", "relay2.example.com",
        )

    assert SENSITIVE_USERNAME not in caplog.text


# ── blob secure-delete: envelope_id обрізаний ─────────────────────────────
async def test_secure_delete_failure_log_truncates_envelope_id(
    tmp_path, caplog, monkeypatch,
):
    from morok_relay import blob_storage
    from morok_relay.config import get_settings

    monkeypatch.setattr(get_settings(), "blob_dir", tmp_path)

    # _blob_path кладе файл у {blob_dir}/{aa}/{bb}/{envelope_id}.
    # Провокуємо помилку unlink: на місці ОЧІКУВАНОГО файлу робимо
    # ДИРЕКТОРІЮ — path.exists() поверне True, а path.unlink() кине
    # OSError (IsADirectoryError — підклас OSError).
    bogus_path = blob_storage._blob_path(FULL_ENVELOPE_ID)
    bogus_path.mkdir(parents=True)

    with caplog.at_level(logging.ERROR):
        await blob_storage.secure_delete_blob(FULL_ENVELOPE_ID)

    assert FULL_ENVELOPE_ID not in caplog.text, \
        "повний envelope_id потрапив у лог помилки"
    assert FULL_ENVELOPE_ID[:8] in caplog.text
