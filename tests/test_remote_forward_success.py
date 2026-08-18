"""
remote_forward() мусить УМІТИ повернути успіх (аудит зовн. №3, HIGH — і
найгірша знахідка за весь марафон).

Баг: `response.raise_for_status()` і `return response.json()` мали
зайвий відступ і опинились МЕРТВИМ КОДОМ усередині `if response is
None: return None`. Функція завжди виходила на `return None` раніше,
ніж встигала глянути на response — незалежно від того, що peer
відповів. HTTP-запит при цьому реально йшов і, найімовірніше, успішно
доходив до одержувача.

Наслідок: federation_worker бачив None як невдачу, ретраїв до 11 разів,
переводив у dead_letter — тримаючи повний ciphertext до 72 годин —
хоча повідомлення могло дійти з першої спроби. Це внесено МНОЮ в
батчі pin-to-IP (копі-паст помилка в одному з чотирьох місць); три
інші виклики (_pinned_get / handshake / snapshot) написані правильно,
тому цей тест — прямий regression на конкретний зламаний виклик, а не
загальна перевірка _pinned_post.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from morok_relay.federation_client import remote_forward

pytestmark = pytest.mark.asyncio


async def test_remote_forward_returns_json_on_success(monkeypatch):
    """ГОЛОВНИЙ ТЕСТ. HTTP 200 з валідним JSON → remote_forward
    повертає цей JSON, а не None."""
    fake_response = MagicMock()
    fake_response.raise_for_status = MagicMock()  # не кидає — 200 OK
    fake_response.json = MagicMock(return_value={"accepted": True, "envelope_id": "ab12"})

    with patch(
        "morok_relay.federation_client._pinned_post",
        new=AsyncMock(return_value=fake_response),
    ):
        result = await remote_forward("relay2.example.com", {"kind": "dm"})

    assert result is not None, "успішна доставка помилково інтерпретована як провал"
    assert result == {"accepted": True, "envelope_id": "ab12"}
    fake_response.raise_for_status.assert_called_once()


async def test_remote_forward_returns_none_on_pin_failure(monkeypatch):
    """Небезпечний host (pin-to-IP відмовив) — None, як і раніше."""
    with patch(
        "morok_relay.federation_client._pinned_post",
        new=AsyncMock(return_value=None),
    ):
        result = await remote_forward("evil.example.com", {"kind": "dm"})
    assert result is None


async def test_remote_forward_returns_none_on_http_error(monkeypatch):
    """Peer відповів помилкою (4xx/5xx) — raise_for_status кидає,
    ловиться, None. Це той шлях, що мав ловитись і РАНІШЕ теж працював —
    перевіряємо, що фікс його не зламав."""
    import httpx

    fake_response = MagicMock()
    fake_response.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError("500", request=MagicMock(), response=MagicMock())
    )

    with patch(
        "morok_relay.federation_client._pinned_post",
        new=AsyncMock(return_value=fake_response),
    ):
        result = await remote_forward("relay2.example.com", {"kind": "dm"})
    assert result is None


async def test_remote_forward_returns_none_when_privkey_missing(monkeypatch):
    """Не сконфігурований privkey — рання відмова, як і раніше."""
    from morok_relay.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "relay_privkey_hex", "not-hex")
    result = await remote_forward("relay2.example.com", {"kind": "dm"})
    assert result is None
