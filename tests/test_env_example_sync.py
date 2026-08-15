"""
.env.example ↔ Settings: розсинхрон має валити CI, а не мовчати.

Settings має extra="ignore" — змінна-привид у прикладі мовчки
ігнорується в бою: адмін пропише security-ліміт і думатиме, що він діє.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_env_example_matches_settings():
    result = subprocess.run(
        [sys.executable, "-m", "tools.check_env_example"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"Розсинхрон .env.example і Settings:\n{result.stdout}{result.stderr}"
    )
