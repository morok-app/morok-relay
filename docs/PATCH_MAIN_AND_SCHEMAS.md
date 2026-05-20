# Patch для morok_relay/main.py — додати backup router.
#
# Зміни МІНІМАЛЬНІ. Не переписувати файл повністю — тільки додати рядки.

# === ЗМІНА 1: в імпортах ===
#
# Знайди рядок:
#
#     from .api import auth, dms, federation, groups, inbox, messages, users
#
# Заміни на:
#
#     from .api import auth, backup, dms, federation, groups, inbox, messages, users


# === ЗМІНА 2: реєстрація роутера ===
#
# Знайди блок з include_router викликами (вкінці файлу):
#
#     app.include_router(auth.router, prefix="/api/v1/auth")
#     app.include_router(users.router, prefix="/api/v1/users")
#     app.include_router(messages.router, prefix="/api/v1/messages")
#     app.include_router(groups.router, prefix="/api/v1/groups")
#     app.include_router(dms.router, prefix="/api/v1/dms")
#     app.include_router(federation.router, prefix="/api/v1/federation")
#
# Після цих рядків (перед "# WebSocket" або перед inbox) додай:
#
#     app.include_router(backup.router, prefix="/api/v1/backup")
#
# Все. Більше нічого не міняй.


# === ЗМІНА 3: schemas.py ===
#
# Відкрий morok_relay/schemas.py. Знайди розділ ENCRYPTED BACKUP — його там
# немає, треба додати.
#
# В самому ВЕРХУ файла, після існуючих імпортів, переконайся що є:
#
#     import base64
#
# Потім додай ВНУТРІ файла (наприклад перед "# HEALTH & ERROR" в кінці):
#
# (вміст з morok_relay/schemas_backup_patch.txt)
