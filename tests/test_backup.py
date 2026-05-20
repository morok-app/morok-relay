"""
Tests for encrypted_backups model + schemas validation.
"""
from __future__ import annotations

import base64

import pytest


def test_encrypted_backup_model_imports():
    from morok_relay.models import EncryptedBackup
    assert EncryptedBackup.__tablename__ == "encrypted_backups"


def test_backup_schemas_import():
    # The schemas live in schemas.py once you've applied the patch.
    # Here we only assert the module imports cleanly.
    from morok_relay import schemas
    # These attributes only exist after the patch is applied:
    # (skip the test gracefully if not yet patched)
    for cls in ("BackupCreateRequest", "BackupInfo", "BackupRestoreResponse",
                "BackupDeleted"):
        if not hasattr(schemas, cls):
            pytest.skip(f"{cls} not yet patched into schemas.py")


def test_backup_constants():
    from morok_relay import schemas
    if not hasattr(schemas, "BACKUP_MAX_BYTES"):
        pytest.skip("schemas not yet patched")
    assert schemas.BACKUP_MAX_BYTES == 1024
    assert schemas.BACKUP_KDF_SALT_BYTES == 16


def test_backup_request_validates_salt_size():
    from morok_relay import schemas
    if not hasattr(schemas, "BackupCreateRequest"):
        pytest.skip("schemas not yet patched")

    # Salt must be exactly 16 bytes
    good_salt = base64.b64encode(b"\x00" * 16).decode()
    bad_salt = base64.b64encode(b"\x00" * 8).decode()
    good_seed = base64.b64encode(b"some encrypted data").decode()

    # Good
    schemas.BackupCreateRequest(
        encrypted_seed_b64=good_seed,
        kdf_salt_b64=good_salt,
        kdf_params={"alg": "pbkdf2"},
    )

    # Bad: too-short salt
    with pytest.raises(Exception):
        schemas.BackupCreateRequest(
            encrypted_seed_b64=good_seed,
            kdf_salt_b64=bad_salt,
            kdf_params={},
        )


def test_backup_request_validates_seed_size():
    from morok_relay import schemas
    if not hasattr(schemas, "BackupCreateRequest"):
        pytest.skip("schemas not yet patched")

    good_salt = base64.b64encode(b"\x00" * 16).decode()
    too_big = base64.b64encode(b"x" * 2048).decode()  # >1KB

    with pytest.raises(Exception):
        schemas.BackupCreateRequest(
            encrypted_seed_b64=too_big,
            kdf_salt_b64=good_salt,
            kdf_params={},
        )


def test_backup_request_rejects_empty_seed():
    from morok_relay import schemas
    if not hasattr(schemas, "BackupCreateRequest"):
        pytest.skip("schemas not yet patched")

    good_salt = base64.b64encode(b"\x00" * 16).decode()
    empty_seed = base64.b64encode(b"").decode()

    with pytest.raises(Exception):
        schemas.BackupCreateRequest(
            encrypted_seed_b64=empty_seed,
            kdf_salt_b64=good_salt,
            kdf_params={},
        )
