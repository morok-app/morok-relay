"""
Звірка .env.example ↔ Settings.

ЧОМУ. Settings має extra="ignore": змінна з помилкою в назві (або та,
що взагалі не існує в Settings) мовчки ігнорується. Адмін пропише
security-ліміт із .env.example, побачить нормальний старт і думатиме,
що ліміт увімкнено. Цей скрипт робить розсинхрон ПОМІТНИМ:

  1. кожна MOROK_-змінна з .env.example мусить існувати як поле Settings;
  2. (м'яко, warning) кожне поле Settings бажано задокументувати
     в .env.example.

Запуск:  python -m tools.check_env_example
Вихід:   0 — синхрон; 1 — у прикладі є змінні-привиди.
Ганяти в CI поряд із ruff/mypy/pytest.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE = REPO_ROOT / ".env.example"

sys.path.insert(0, str(REPO_ROOT))

from morok_relay.config import Settings  # noqa: E402

ENV_PREFIX = Settings.model_config.get("env_prefix", "MOROK_")

VAR_RE = re.compile(r"^([A-Z][A-Z0-9_]*)=", re.MULTILINE)


def main() -> int:
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    example_vars = set(VAR_RE.findall(text))

    settings_env_names = {
        f"{ENV_PREFIX}{name.upper()}" for name in Settings.model_fields
    }

    ghosts = sorted(v for v in example_vars if v not in settings_env_names)
    undocumented = sorted(v for v in settings_env_names if v not in example_vars)

    ok = True
    if ghosts:
        ok = False
        print("ПОМИЛКА: змінні з .env.example, яких Settings НЕ читає")
        print("(extra='ignore' — вони мовчки ігноруються в бою):")
        for v in ghosts:
            print(f"  - {v}")

    if undocumented:
        print("\nWARNING: поля Settings без прикладу в .env.example:")
        for v in undocumented:
            print(f"  - {v}")

    if ok:
        print(f"OK: усі {len(example_vars)} змінних .env.example існують у Settings.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
