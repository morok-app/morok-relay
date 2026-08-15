"""
Installer: torrc-міграція та .env-upsert (аудит 3, обидва P1).

Ключовий принцип: тестуємо КОМАНДИ З РЕАЛЬНОГО install.sh, а не їх
копію в тесті — sed-рядок і функція upsert_env витягуються з файлу на
льоту. Розсинхрон тесту з installer'ом неможливий.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = (REPO_ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")


def _extract_torrc_sed() -> str:
    for line in INSTALL_SH.splitlines():
        if line.strip().startswith("sed -i") and "HiddenServiceDir" in line:
            return line.strip()
    raise AssertionError("torrc sed-рядок не знайдено в install.sh")


def _extract_upsert_env() -> str:
    m = re.search(r"upsert_env\(\) \{.*?\n\}", INSTALL_SH, re.DOTALL)
    assert m, "функція upsert_env не знайдена в install.sh"
    return m.group(0)


# ── torrc ────────────────────────────────────────────────────────────────
OLD_TORRC = """\
SocksPort 9050
# чужий onion на цьому ж хості — НЕ ЧІПАТИ
HiddenServiceDir /var/lib/tor/other_service/
HiddenServicePort 80 127.0.0.1:8000

# --- Morok relay onion service ---
HiddenServiceDir /var/lib/tor/morok_relay/
HiddenServicePort 80 127.0.0.1:8000
"""


def test_torrc_migration_moves_only_morok_block(tmp_path):
    torrc = tmp_path / "torrc"
    torrc.write_text(OLD_TORRC, encoding="utf-8")

    cmd = _extract_torrc_sed().replace('"$TORRC"', str(torrc))
    subprocess.run(["bash", "-c", cmd], check=True)

    result = torrc.read_text(encoding="utf-8")
    lines = result.splitlines()
    morok_i = lines.index("HiddenServiceDir /var/lib/tor/morok_relay/")
    other_i = lines.index("HiddenServiceDir /var/lib/tor/other_service/")

    assert lines[morok_i + 1] == "HiddenServicePort 80 127.0.0.1:8081", \
        "morok-блок не мігрував на nginx-listener"
    assert lines[other_i + 1] == "HiddenServicePort 80 127.0.0.1:8000", \
        "sed зачепив ЧУЖИЙ onion-сервіс!"


def test_torrc_migration_idempotent(tmp_path):
    torrc = tmp_path / "torrc"
    torrc.write_text(OLD_TORRC, encoding="utf-8")
    cmd = _extract_torrc_sed().replace('"$TORRC"', str(torrc))
    subprocess.run(["bash", "-c", cmd], check=True)
    once = torrc.read_text()
    subprocess.run(["bash", "-c", cmd], check=True)
    assert torrc.read_text() == once


# ── .env upsert ──────────────────────────────────────────────────────────
OPERATOR_ENV = """\
MOROK_IS_PRODUCTION=true
MOROK_RELAY_NAME=old.example.com
# --- ручні бойові налаштування оператора ---
MOROK_MAIL_OUT_TOKEN=super-secret-operator-value
MOROK_ADMIN_USERNAME=boss
MOROK_TRUSTED_PROXY_IPS=127.0.0.1,::1,10.0.0.5
MOROK_RATE_LIMIT_MESSAGES_PER_MINUTE=120
"""


def _run_upserts(env_file: Path, pairs: list[tuple[str, str]]) -> None:
    fn = _extract_upsert_env()
    calls = "\n".join(f'upsert_env {k} "{v}"' for k, v in pairs)
    script = f'ENV_FILE="{env_file}"\n{fn}\n{calls}\n'
    subprocess.run(["bash", "-c", script], check=True)


def test_upsert_preserves_operator_keys(tmp_path):
    """Головна вимога P1: повторний install.sh НЕ скидає бойовий конфіг."""
    env = tmp_path / ".env"
    env.write_text(OPERATOR_ENV, encoding="utf-8")

    # те, що робить installer при повторному запуску
    _run_upserts(env, [
        ("MOROK_IS_PRODUCTION", "true"),
        ("MOROK_RELAY_NAME", "new.example.com"),
        ("MOROK_DB_DSN", "postgresql+asyncpg://u:p@localhost:5432/db"),
    ])

    text = env.read_text(encoding="utf-8")
    # оператора не чіпали
    assert "MOROK_MAIL_OUT_TOKEN=super-secret-operator-value" in text
    assert "MOROK_ADMIN_USERNAME=boss" in text
    assert "MOROK_TRUSTED_PROXY_IPS=127.0.0.1,::1,10.0.0.5" in text
    assert "MOROK_RATE_LIMIT_MESSAGES_PER_MINUTE=120" in text
    # відомі ключі оновлено на місці, без дублів
    assert text.count("MOROK_RELAY_NAME=") == 1
    assert "MOROK_RELAY_NAME=new.example.com" in text
    # новий ключ дописано
    assert "MOROK_DB_DSN=postgresql+asyncpg://u:p@localhost:5432/db" in text


def test_upsert_rerun_idempotent(tmp_path):
    env = tmp_path / ".env"
    env.write_text(OPERATOR_ENV, encoding="utf-8")
    pairs = [("MOROK_RELAY_NAME", "x.example.com"), ("MOROK_DEBUG", "false")]
    _run_upserts(env, pairs)
    once = env.read_text()
    _run_upserts(env, pairs)
    assert env.read_text() == once, "повторний запуск змінює файл"


def test_upsert_no_duplicate_lines(tmp_path):
    env = tmp_path / ".env"
    env.write_text("", encoding="utf-8")
    _run_upserts(env, [("MOROK_DEBUG", "false")] * 3)
    assert env.read_text().count("MOROK_DEBUG=") == 1


# ── синтаксис installer'а ────────────────────────────────────────────────
def test_install_sh_bash_syntax():
    subprocess.run(
        ["bash", "-n", str(REPO_ROOT / "deploy" / "install.sh")], check=True,
    )


def test_install_sh_shellcheck():
    if subprocess.run(["which", "shellcheck"], capture_output=True).returncode:
        pytest.skip("shellcheck не встановлено")
    subprocess.run(
        ["shellcheck", "-S", "warning", str(REPO_ROOT / "deploy" / "install.sh")],
        check=True,
    )
