"""
Encrypted seed backup endpoints — premium feature.

The relay stores only client-encrypted bytes. It never sees the seed in
plaintext. Restore-flow is unauthenticated by design (the user has no
session yet — that's why they're restoring) but rate-limited heavily.

Endpoints
---------
POST   /api/v1/backup              — create/replace my backup       (auth)
GET    /api/v1/backup              — get my own backup              (auth)
DELETE /api/v1/backup              — delete my backup               (auth)
GET    /api/v1/backup/by-username/{u} — public restore lookup       (no auth)

Tier requirement
----------------
Backup is a PREMIUM feature. Free-tier users get 403 on POST. They can
still DELETE if they previously had backup (e.g. tier downgrade).
"""
from __future__ import annotations

import base64
import logging
import time

from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy import select

from ..config import get_settings
from ..deps import CurrentSession, DBSession, RedisClient
from ..models import EncryptedBackup, User, UserTier
from ..rate_limit import rate_limit_by_pubkey, rate_limit_tor_aware_by_path_param
from ..sensitive_action import verify_sensitive_action
from ..schemas import (
    SensitiveActionProof,
    BackupCreateRequest,
    BackupDeleted,
    BackupInfo,
    BackupRestoreResponse,
    normalize_username,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["backup"])


def _to_info(b: EncryptedBackup) -> BackupInfo:
    return BackupInfo(
        encrypted_seed_b64=base64.b64encode(b.encrypted_seed).decode(),
        kdf_salt_b64=base64.b64encode(b.kdf_salt).decode(),
        kdf_params=b.kdf_params,
        schema_version=b.schema_version,
        created_at=b.created_at,
        updated_at=b.updated_at,
    )


@router.post(
    "",
    response_model=BackupInfo,
    summary="Create or replace my encrypted seed backup (premium)",
    dependencies=[Depends(rate_limit_by_pubkey(
        "backup_create",
        # 10/min is generous — typical user does this once
        get_settings().rate_limit_messages_per_minute,
    ))],
)
async def create_or_replace_backup(
    body: BackupCreateRequest,
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
) -> BackupInfo:
    pubkey_bytes = bytes.fromhex(current.pubkey_hex)

    # Tier check — load user
    stmt = select(User).where(User.pubkey == pubkey_bytes)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="user_not_found_call_me_first",
        )

    if user.tier == UserTier.FREE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="backup_requires_premium",
        )

    encrypted_seed = base64.b64decode(body.encrypted_seed_b64, validate=True)
    kdf_salt = base64.b64decode(body.kdf_salt_b64, validate=True)
    now = int(time.time())

    # Upsert: one backup per pubkey
    stmt = select(EncryptedBackup).where(EncryptedBackup.pubkey == pubkey_bytes)
    backup = (await db.execute(stmt)).scalar_one_or_none()

    # Крипто-підтвердження (аудит зовн. №5, P1). Якщо клієнт ПЕРЕДАВ
    # підпис — перевіряємо fail-closed, незалежно від того, це заміна
    # чи перше створення (раз уже надіслав, недійсний підпис
    # підозріліший за його повну відсутність). Якщо підпису немає
    # взагалі — legacy bearer-only шлях, без змін (поки клієнти не
    # підтримають підписування) — заміна БЕЗ підпису й далі можлива,
    # це свідомий компроміс сумісності, не діра, що з'явилась щойно.
    if body.action_signature_hex is not None:
        settings = get_settings()
        valid = await verify_sensitive_action(
            redis,
            action="backup_replace",
            pubkey_hex=current.pubkey_hex,
            target=current.pubkey_hex,
            nonce=body.action_nonce or "",
            timestamp=body.action_timestamp or 0,
            signature_hex=body.action_signature_hex,
            relay_name=settings.relay_name,
        )
        if not valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_action_proof",
            )

    if backup is not None:
        backup.encrypted_seed = encrypted_seed
        backup.kdf_salt = kdf_salt
        backup.kdf_params = body.kdf_params
        backup.schema_version = body.schema_version
        backup.username_at_backup = user.username
        backup.updated_at = now
    else:
        backup = EncryptedBackup(
            pubkey=pubkey_bytes,
            username_at_backup=user.username,
            encrypted_seed=encrypted_seed,
            kdf_salt=kdf_salt,
            kdf_params=body.kdf_params,
            schema_version=body.schema_version,
            created_at=now,
            updated_at=now,
        )
        db.add(backup)

    await db.flush()

    logger.info(
        "Backup stored: pubkey=%s..., size=%d bytes, version=%d",
        current.pubkey_hex[:16], len(encrypted_seed), body.schema_version,
    )

    return _to_info(backup)


@router.get(
    "",
    response_model=BackupInfo,
    summary="Get my own backup",
)
async def get_my_backup(
    current: CurrentSession,
    db: DBSession,
) -> BackupInfo:
    pubkey_bytes = bytes.fromhex(current.pubkey_hex)
    stmt = select(EncryptedBackup).where(EncryptedBackup.pubkey == pubkey_bytes)
    backup = (await db.execute(stmt)).scalar_one_or_none()

    if backup is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no_backup",
        )

    return _to_info(backup)


@router.delete(
    "",
    response_model=BackupDeleted,
    summary="Delete my backup",
)
async def delete_my_backup(
    current: CurrentSession,
    db: DBSession,
    redis: RedisClient,
    proof: SensitiveActionProof | None = Body(default=None),
) -> BackupDeleted:
    pubkey_bytes = bytes.fromhex(current.pubkey_hex)
    stmt = select(EncryptedBackup).where(EncryptedBackup.pubkey == pubkey_bytes)
    backup = (await db.execute(stmt)).scalar_one_or_none()

    if backup is None:
        return BackupDeleted(deleted=False)

    # Крипто-підтвердження (аудит зовн. №5, P1) — див. sensitive_action.py.
    if proof is not None and proof.action_signature_hex is not None:
        settings = get_settings()
        valid = await verify_sensitive_action(
            redis,
            action="backup_delete",
            pubkey_hex=current.pubkey_hex,
            target=current.pubkey_hex,
            nonce=proof.action_nonce or "",
            timestamp=proof.action_timestamp or 0,
            signature_hex=proof.action_signature_hex,
            relay_name=settings.relay_name,
        )
        if not valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_action_proof",
            )

    await db.delete(backup)
    await db.flush()

    logger.info("Backup deleted: pubkey=%s...", current.pubkey_hex[:16])
    return BackupDeleted(deleted=True)


@router.get(
    "/by-username/{username}",
    response_model=BackupRestoreResponse,
    summary="Public restore lookup — heavily rate-limited",
    dependencies=[Depends(rate_limit_tor_aware_by_path_param(
        "backup_restore",
        # Tight: 3 per 60s per IP. Defense against online brute-force.
        # Offline brute-force depends on client PIN strength.
        3,
        "username",
    ))],
)
async def restore_by_username(
    username: str,
    db: DBSession,
) -> BackupRestoreResponse:
    """
    Unauthenticated restore lookup.

    User on a new device knows their username and PIN. They call this
    endpoint, get the encrypted blob + KDF params, then derive the key
    from PIN locally and decrypt.

    We do NOT confirm whether the username "has backup" before returning —
    the same 404 is returned for both "no such user" and "user has no
    backup", so an attacker can't enumerate which usernames have backups.

    Heavily rate-limited (3/min per IP) to prevent online brute-force.
    """
    normalized = normalize_username(username)

    # Look up user by username
    stmt = (
        select(User)
        .where(User.username == normalized)
        .where(User.deleted_at.is_(None))
    )
    user = (await db.execute(stmt)).scalar_one_or_none()

    if user is None:
        # Indistinguishable from "no backup" below
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no_backup_or_no_user",
        )

    stmt = select(EncryptedBackup).where(EncryptedBackup.pubkey == user.pubkey)
    backup = (await db.execute(stmt)).scalar_one_or_none()
    if backup is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no_backup_or_no_user",
        )

    return BackupRestoreResponse(
        encrypted_seed_b64=base64.b64encode(backup.encrypted_seed).decode(),
        kdf_salt_b64=base64.b64encode(backup.kdf_salt).decode(),
        kdf_params=backup.kdf_params,
        schema_version=backup.schema_version,
    )
