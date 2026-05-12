"""
Tests for reaper file iteration logic.

Full reaper test requires Redis + filesystem; here we just check the
filename filtering rules.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from morok_relay.scripts.reaper import _iter_blob_paths


def test_iter_skips_short_filenames():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "ab").mkdir()
        (root / "ab" / "cd").mkdir()
        (root / "ab" / "cd" / "short").write_bytes(b"x")
        paths = list(_iter_blob_paths(root))
        assert paths == []


def test_iter_skips_tmp_files():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        # Build a valid-looking blob path with .tmp suffix
        sub = root / "aa" / "bb"
        sub.mkdir(parents=True)
        (sub / ("a" * 64 + ".tmp")).write_bytes(b"x")
        paths = list(_iter_blob_paths(root))
        assert paths == []


def test_iter_finds_valid_blobs():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        valid_id = "a" * 64
        sub = root / "aa" / "aa"
        sub.mkdir(parents=True)
        (sub / valid_id).write_bytes(b"encrypted-blob-bytes")
        paths = list(_iter_blob_paths(root))
        assert len(paths) == 1
        assert paths[0].name == valid_id


def test_iter_skips_non_hex_filenames():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        sub = root / "zz" / "zz"
        sub.mkdir(parents=True)
        # 64 chars but contains 'g' which isn't hex
        (sub / ("g" * 64)).write_bytes(b"x")
        paths = list(_iter_blob_paths(root))
        assert paths == []


def test_iter_handles_missing_dir():
    """Should not crash if blob dir doesn't exist yet."""
    paths = list(_iter_blob_paths(Path("/nonexistent/path/zzzz")))
    assert paths == []
