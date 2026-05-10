.PHONY: help install run test lint format check clean keygen

PY := python3.12
VENV := .venv
PIP := $(VENV)/bin/pip
PYTHON := $(VENV)/bin/python

help:
	@echo "Morok Relay — development commands"
	@echo ""
	@echo "  make install   Set up venv and install dependencies"
	@echo "  make run       Run dev server with auto-reload"
	@echo "  make test      Run all tests"
	@echo "  make lint      Run ruff + mypy"
	@echo "  make format    Auto-format with black + ruff"
	@echo "  make check     Run lint + tests (CI-style)"
	@echo "  make keygen    Generate a relay keypair"
	@echo "  make clean     Remove venv and caches"

install:
	$(PY) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo ""
	@echo "Done. Activate with: source $(VENV)/bin/activate"

run:
	$(VENV)/bin/uvicorn morok_relay.main:app --reload --host 0.0.0.0 --port 8000

test:
	$(VENV)/bin/pytest -v

lint:
	$(VENV)/bin/ruff check morok_relay tests
	$(VENV)/bin/mypy morok_relay

format:
	$(VENV)/bin/black morok_relay tests
	$(VENV)/bin/ruff check --fix morok_relay tests

check: lint test

keygen:
	$(PYTHON) -m morok_relay.scripts.generate_relay_keypair

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
