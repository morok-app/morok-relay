"""
Unit tests for federation worker backoff logic and module sanity.
"""
from __future__ import annotations

import pytest


def test_module_imports():
    from morok_relay.scripts import federation_worker
    assert hasattr(federation_worker, "backoff_seconds")
    assert hasattr(federation_worker, "process_row")
    assert hasattr(federation_worker, "run_once")


def test_backoff_schedule():
    from morok_relay.scripts.federation_worker import backoff_seconds

    # 1st retry: 30s
    assert backoff_seconds(1) == 30
    # 2nd retry: 1m
    assert backoff_seconds(2) == 60
    # 3rd retry: 2m
    assert backoff_seconds(3) == 120
    # 5th retry: 15m
    assert backoff_seconds(5) == 900
    # 10th retry: 8h
    assert backoff_seconds(10) == 28800


def test_backoff_above_schedule_caps():
    """Even if called with attempt count > 10, return the max."""
    from morok_relay.scripts.federation_worker import backoff_seconds
    # Caller is supposed to dead-letter at attempt 11+, but if called,
    # we still return a sane number rather than crash.
    assert backoff_seconds(11) == 28800
    assert backoff_seconds(20) == 28800


def test_max_attempts_constant():
    from morok_relay.scripts.federation_worker import MAX_ATTEMPTS
    # Stas's design: 11 attempts before dead-letter
    assert MAX_ATTEMPTS == 11


def test_in_flight_timeout_constant():
    from morok_relay.scripts.federation_worker import IN_FLIGHT_TIMEOUT_SECONDS
    # Stuck rows recovered after 5 minutes
    assert IN_FLIGHT_TIMEOUT_SECONDS == 300


def test_batch_size_constant():
    from morok_relay.scripts.federation_worker import BATCH_SIZE
    assert BATCH_SIZE == 50


def test_fed_queue_status_enum():
    from morok_relay.models import FedQueueStatus
    assert FedQueueStatus.PENDING.value == "pending"
    assert FedQueueStatus.IN_FLIGHT.value == "in_flight"
    assert FedQueueStatus.SUCCEEDED.value == "succeeded"
    assert FedQueueStatus.DEAD_LETTER.value == "dead_letter"
