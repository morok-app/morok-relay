#!/usr/bin/env bash
#
# Morok Relay — one-command self-host installer.
#
#   curl -fsSL https://morok.app/install.sh | sudo bash
#
# Brings up a complete, production-ready Morok relay on a fresh Ubuntu
# 22.04 / 24.04 server: PostgreSQL, Redis, Python venv, database
# migrations, relay keypair, all systemd services + timers, nginx with
# a Let's Encrypt TLS certificate, and a Tor onion address.
#
# The ONLY things it asks for are your domain and an email (for the
# certificate). Everything else — passwords, keys — is generated.
#
# After it finishes, the only manual steps left are:
#   1. Point a DNS A-record at this server (it can't touch your registrar).
#   2. Run one handshake command to federate with an existing relay.
#
# Re-runnable: safe to run again; it skips steps already done.
# ---------------------------------------------------------------------------

set -euo pipefail

# ===========================================================================
# Constants
# ===========================================================================
REPO_URL="https://github.com/morok-app/morok-relay.git"
MOROK_USER="morok"
INSTALL_DIR="/home/${MOROK_USER}/morok-relay"
BLOB_DIR="/var/lib/morok/blobs"
DB_NAME="morok_relay"
DB_USER="morok"
PY_MIN_MINOR=12   # require python3.12+ — pyproject каже >=3.12,
                  # дозволяти тут 3.11 означало «в мене працює, у
                  # self-host — дивні runtime-проблеми» (аудит зовн. №2)

C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_GREEN=$'\e[32m'
C_BLUE=$'\e[34m'; C_YELLOW=$'\e[33m'; C_RED=$'\e[31m'; C_DIM=$'\e[2m'

step()  { echo; echo "${C_BLUE}${C_BOLD}==>${C_RESET}${C_BOLD} $*${C_RESET}"; }
ok()    { echo "  ${C_GREEN}✓${C_RESET} $*"; }
warn()  { echo "  ${C_YELLOW}!${C_RESET} $*"; }
die()   { echo "${C_RED}${C_BOLD}✗ $*${C_RESET}" >&2; exit 1; }

# ===========================================================================
# Pre-flight
# ===========================================================================
[[ $EUID -eq 0 ]] || die "Run as root (use sudo)."
[[ -f /etc/os-release ]] || die "Cannot detect OS (no /etc/os-release)."
. /etc/os-release
[[ "${ID:-}" == "ubuntu" || "${ID_LIKE:-}" == *debian* ]] \
  || warn "Tested on Ubuntu/Debian. ${PRETTY_NAME:-this OS} may differ."

echo
echo "${C_BOLD}  Morok Relay — self-host installer${C_RESET}"
echo "${C_DIM}  A federated, metadata-minimizing messenger relay.${C_RESET}"
echo

# ===========================================================================
# Gather input (the only two questions)
# ===========================================================================
# Allow non-interactive use via env vars: MOROK_DOMAIN, MOROK_EMAIL.
DOMAIN="${MOROK_DOMAIN:-}"
EMAIL="${MOROK_EMAIL:-}"

if [[ -z "$DOMAIN" ]]; then
  read -rp "  Your relay domain (e.g. relay.example.com): " DOMAIN
fi
[[ -n "$DOMAIN" ]] || die "Domain is required."
[[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || die "That doesn't look like a domain: $DOMAIN"

if [[ -z "$EMAIL" ]]; then
  read -rp "  Email for the TLS certificate (Let's Encrypt): " EMAIL
fi
[[ -n "$EMAIL" ]] || die "Email is required for the certificate."

echo
echo "  Domain : ${C_BOLD}${DOMAIN}${C_RESET}"
echo "  Email  : ${C_BOLD}${EMAIL}${C_RESET}"
echo
read -rp "  Proceed? [Y/n] " yn
[[ "${yn:-Y}" =~ ^[Yy]?$ ]] || die "Aborted."

# ===========================================================================
# 1. System packages
# ===========================================================================
step "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  git curl ca-certificates \
  python3 python3-venv python3-dev build-essential \
  postgresql postgresql-contrib \
  redis-server \
  nginx \
  tor \
  certbot python3-certbot-nginx \
  >/dev/null
ok "Packages installed"

# Verify python version
PY_MINOR="$(python3 -c 'import sys; print(sys.version_info.minor)')"
[[ "$PY_MINOR" -ge "$PY_MIN_MINOR" ]] \
  || die "Python 3.${PY_MIN_MINOR}+ required, found 3.${PY_MINOR}."
ok "Python 3.${PY_MINOR}"

# ===========================================================================
# 2. Service user
# ===========================================================================
step "Creating service user '${MOROK_USER}'"
if id "$MOROK_USER" &>/dev/null; then
  ok "User already exists"
else
  adduser --system --group --home "/home/${MOROK_USER}" --shell /usr/sbin/nologin "$MOROK_USER"
  ok "User created"
fi

# ===========================================================================
# 3. Fetch code
# ===========================================================================
step "Fetching relay source"
if [[ -d "${INSTALL_DIR}/.git" ]]; then
  sudo -u "$MOROK_USER" git -C "$INSTALL_DIR" pull --ff-only
  ok "Updated existing checkout"
else
  sudo -u "$MOROK_USER" git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
  ok "Cloned $REPO_URL"
fi

# ===========================================================================
# 4. Python venv + deps
# ===========================================================================
step "Setting up Python virtual environment"
if [[ ! -d "${INSTALL_DIR}/.venv" ]]; then
  sudo -u "$MOROK_USER" python3 -m venv "${INSTALL_DIR}/.venv"
fi
sudo -u "$MOROK_USER" "${INSTALL_DIR}/.venv/bin/pip" install --quiet --upgrade pip
sudo -u "$MOROK_USER" "${INSTALL_DIR}/.venv/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt"
ok "Dependencies installed"

# ===========================================================================
# 5. PostgreSQL
# ===========================================================================
step "Configuring PostgreSQL"
systemctl enable --now postgresql >/dev/null 2>&1 || true

# --- ПОВТОРНИЙ ЗАПУСК: перечитуємо наявні секрети ---------------------------
# Скрипт документовано як re-runnable, і він САМ радить перезапуск після
# налаштування DNS. Тому секрети НЕ можна перегенеровувати наосліп:
#  * новий relay privkey = втрата федеративної identity (усі, хто довіряв
#    старому pubkey, почнуть відхиляти цей релей);
#  * новий DB-пароль сам по собі безпечний (роль ALTER-иться), але тримаємо
#    старий, щоб .env і база не розʼїхались, якщо скрипт впаде посередині.
EXISTING_ENV="${INSTALL_DIR}/.env"
OLD_DB_PASS=""; OLD_RELAY_PUB=""; OLD_RELAY_PRIV=""
if [[ -f "$EXISTING_ENV" ]]; then
  OLD_DB_PASS="$(sed -n 's|^MOROK_DB_DSN=postgresql+asyncpg://[^:]*:\([^@]*\)@.*|\1|p' "$EXISTING_ENV" | head -1)"
  OLD_RELAY_PUB="$(sed -n 's/^MOROK_RELAY_PUBKEY_HEX=\([0-9a-fA-F]\{64\}\).*/\1/p'  "$EXISTING_ENV" | head -1)"
  OLD_RELAY_PRIV="$(sed -n 's/^MOROK_RELAY_PRIVKEY_HEX=\([0-9a-fA-F]\{64\}\).*/\1/p' "$EXISTING_ENV" | head -1)"
  [[ -n "$OLD_RELAY_PRIV" ]] && ok "Found existing relay identity — will preserve it"
fi

if [[ -n "$OLD_DB_PASS" ]]; then
  DB_PASS="$OLD_DB_PASS"
else
  DB_PASS="$(openssl rand -hex 24)"
fi
# Create role if missing
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1; then
  sudo -u postgres psql -qc "ALTER ROLE ${DB_USER} WITH PASSWORD '${DB_PASS}';"
  ok "DB role updated"
else
  sudo -u postgres psql -qc "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';"
  ok "DB role created"
fi
# Create database if missing
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1; then
  ok "Database already exists"
else
  sudo -u postgres createdb -O "${DB_USER}" "${DB_NAME}"
  ok "Database created"
fi

# ===========================================================================
# 6. Redis (default localhost config is fine; just ensure running)
# ===========================================================================
step "Enabling Redis"
systemctl enable --now redis-server >/dev/null 2>&1 || systemctl enable --now redis >/dev/null 2>&1 || true
ok "Redis running"

# ===========================================================================
# 7. Blob storage dir
# ===========================================================================
step "Creating blob storage"
mkdir -p "$BLOB_DIR"
chown -R "${MOROK_USER}:${MOROK_USER}" /var/lib/morok
chmod 700 "$BLOB_DIR"
ok "$BLOB_DIR"

# ===========================================================================
# 8. Relay keypair
# ===========================================================================
step "Generating relay identity keypair (Ed25519)"
if [[ -n "$OLD_RELAY_PUB" && -n "$OLD_RELAY_PRIV" ]]; then
  # КРИТИЧНО: цей ключ — постійна identity релея у федерації. Перегенерація
  # розірвала б довіру з усіма пірами. Зберігаємо наявний.
  RELAY_PUB="$OLD_RELAY_PUB"
  RELAY_PRIV="$OLD_RELAY_PRIV"
  ok "Reusing existing keypair: ${RELAY_PUB}"
else
  KEYS="$(sudo -u "$MOROK_USER" bash -c "cd '$INSTALL_DIR' && .venv/bin/python -m morok_relay.scripts.generate_relay_keypair")"
  # Generator prints lines like:
  #   MOROK_RELAY_PUBKEY_HEX=<64hex>
  #   MOROK_RELAY_PRIVKEY_HEX=<64hex>
  # Parse by variable name (robust against extra hex in comments/output).
  RELAY_PUB="$(echo "$KEYS"  | grep -oP 'MOROK_RELAY_PUBKEY_HEX=\K[0-9a-fA-F]{64}'  | head -1)"
  RELAY_PRIV="$(echo "$KEYS" | grep -oP 'MOROK_RELAY_PRIVKEY_HEX=\K[0-9a-fA-F]{64}' | head -1)"
  [[ -n "$RELAY_PUB" && -n "$RELAY_PRIV" ]] || die "Could not parse relay keypair from generator output."
  ok "Public key: ${RELAY_PUB}"
fi

# ===========================================================================
# 9. Tor onion service
# ===========================================================================
step "Configuring Tor hidden service"
TORRC="/etc/tor/torrc"
# МІГРАЦІЯ, а не "додати, якщо відсутній": стара версія installer'а
# вказувала HiddenServicePort прямо на uvicorn (:8000). Релей,
# встановлений до фіксу, після git pull отримував безпечний
# nginx-listener, але torrc лишався з :8000 — Tor ходив ПОВЗ nginx,
# і спуфінг X-Real-IP з onion жив далі. Тепер завжди приводимо порт
# СВОГО блока до поточного значення.
if ! grep -q "morok_relay" "$TORRC" 2>/dev/null; then
  cat >> "$TORRC" <<EOF

# --- Morok relay onion service ---
# Вказує на ВИДІЛЕНИЙ nginx-listener (127.0.0.1:8081), а НЕ прямо на
# uvicorn: інакше onion-клієнт спілкується з бекендом з адреси 127.0.0.1,
# яка вважається довіреним проксі, і може підробляти X-Real-IP,
# обходячи всі IP-ліміти. nginx перезаписує ці заголовки.
HiddenServiceDir /var/lib/tor/morok_relay/
HiddenServicePort 80 127.0.0.1:8081
EOF
  ok "Tor onion block added to torrc"
elif grep -qE "^HiddenServicePort 80 127\.0\.0\.1:8000" "$TORRC"; then
  cp -a "$TORRC" "${TORRC}.bak.$(date +%s)"
  # Мігруємо лише рядок одразу ПІСЛЯ нашого HiddenServiceDir — чужі
  # onion-сервіси на цьому ж хості не чіпаємо.
  sed -i '\|^HiddenServiceDir /var/lib/tor/morok_relay/|{n;s|^HiddenServicePort 80 127\.0\.0\.1:8000$|HiddenServicePort 80 127.0.0.1:8081|}' "$TORRC"
  if grep -A1 "^HiddenServiceDir /var/lib/tor/morok_relay/" "$TORRC" | grep -q ":8081"; then
    ok "torrc MIGRATED: morok onion now points at nginx listener :8081"
  else
    warn "torrc migration did not apply — edit $TORRC manually: morok block must point at 127.0.0.1:8081"
  fi
else
  ok "torrc morok block already current"
fi
systemctl enable tor >/dev/null 2>&1 || true
systemctl restart tor
# Wait for the hostname file to appear
ONION=""
for _ in $(seq 1 20); do
  if [[ -f /var/lib/tor/morok_relay/hostname ]]; then
    ONION="$(cat /var/lib/tor/morok_relay/hostname)"
    break
  fi
  sleep 1
done
[[ -n "$ONION" ]] && ok "Onion: ${ONION}" || warn "Onion not ready yet (check 'cat /var/lib/tor/morok_relay/hostname' later)"

# ===========================================================================
# 10. Write .env
# ===========================================================================
step "Writing configuration (.env)"
ENV_FILE="${INSTALL_DIR}/.env"
# UPSERT, а не перезапис: installer знає лише СВОЇ ключі. Реальний бойовий
# .env містить значно більше (mail, admin credentials, proxy trust,
# кастомні ліміти, push) — стара версія генерувала файл "з нуля" і
# повторний запуск тихо скидав ці налаштування до дефолтів (README при
# цьому подає installer як re-runnable). Тепер: відомий ключ — оновлюємо
# значення на місці; відсутній — дописуємо; НЕВІДОМІ РЯДКИ НЕ ЧІПАЄМО.
if [[ -f "$ENV_FILE" ]]; then
  cp -a "$ENV_FILE" "${ENV_FILE}.bak.$(date +%s)"
  ok "Previous .env backed up"
else
  touch "$ENV_FILE"
fi

# upsert_env KEY VALUE — замінити рядок KEY=... або дописати в кінець.
# NOTE: never put a comment '#' on the same line as a secret without a
# leading space — pydantic reads the whole line otherwise.
upsert_env() {
  local key="$1" value="$2"
  if grep -qE "^${key}=" "$ENV_FILE"; then
    # sed з | як роздільником; значення у нас без | (hex, url, шляхи)
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

upsert_env MOROK_IS_PRODUCTION true
upsert_env MOROK_DEBUG false
upsert_env MOROK_RELAY_NAME "${DOMAIN}"
upsert_env MOROK_DB_DSN "postgresql+asyncpg://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}"
upsert_env MOROK_REDIS_URL "redis://localhost:6379/0"
upsert_env MOROK_BLOB_DIR "${BLOB_DIR}"
upsert_env MOROK_RELAY_PUBKEY_HEX "${RELAY_PUB}"
upsert_env MOROK_RELAY_PRIVKEY_HEX "${RELAY_PRIV}"
[[ -n "$ONION" ]] && upsert_env MOROK_TOR_ONION_ADDRESS "${ONION}"

chown "${MOROK_USER}:${MOROK_USER}" "$ENV_FILE"
chmod 600 "$ENV_FILE"
ok "Wrote $ENV_FILE (mode 600, operator keys preserved)"

# ===========================================================================
# 11. Database migrations
# ===========================================================================
step "Running database migrations"
sudo -u "$MOROK_USER" bash -c "cd '$INSTALL_DIR' && .venv/bin/alembic upgrade head"
ok "Schema at head"

# ===========================================================================
# 12. systemd units
# ===========================================================================
step "Installing systemd services + timers"

# 12a. main relay
cat > /etc/systemd/system/morok-relay.service <<EOF
[Unit]
Description=Morok Relay — federated messenger relay server
After=network.target postgresql.service redis-server.service
Requires=postgresql.service redis-server.service

[Service]
Type=simple
User=${MOROK_USER}
Group=${MOROK_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/.venv/bin/uvicorn morok_relay.main:app --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=5s
StartLimitInterval=60s
StartLimitBurst=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
# ЗВУЖЕНО (аудит зовн. №2, П.11): раніше тут був увесь \${INSTALL_DIR} —
# тобто процес міг писати у ВЛАСНИЙ python-код і .env. Після RCE це
# готовий persistence: переписав файл → дочекався рестарту. Тепер код,
# venv і .env для процесу read-only; писати можна лише в дані.
ReadWritePaths=/var/lib/morok
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
StandardOutput=journal
StandardError=journal
SyslogIdentifier=morok-relay

[Install]
WantedBy=multi-user.target
EOF

# Helper to emit a oneshot service + timer pair.
# args: name  description  module  oncalendar_or_interval  is_interval(bool)
emit_timer() {
  local name="$1" desc="$2" module="$3" sched="$4" interval="$5"
  cat > "/etc/systemd/system/morok-${name}.service" <<EOF
[Unit]
Description=${desc}
After=morok-relay.service

[Service]
Type=oneshot
User=${MOROK_USER}
Group=${MOROK_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/.venv/bin/python -m morok_relay.scripts.${module}
SyslogIdentifier=morok-${name}
# Той самий hardening, що й у основного сервісу (аудит зовн. №2, П.11):
# воркери читають той самий .env з ключами і ходять у ту саму БД, але
# раніше не мали ЖОДНОГО із цих обмежень.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/morok
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
EOF
  if [[ "$interval" == "true" ]]; then
    cat > "/etc/systemd/system/morok-${name}.timer" <<EOF
[Unit]
Description=Schedule: ${desc}

[Timer]
OnBootSec=30s
OnUnitActiveSec=${sched}
AccuracySec=2s
Persistent=true

[Install]
WantedBy=timers.target
EOF
  else
    cat > "/etc/systemd/system/morok-${name}.timer" <<EOF
[Unit]
Description=Schedule: ${desc}

[Timer]
OnCalendar=${sched}
Persistent=true

[Install]
WantedBy=timers.target
EOF
  fi
}

emit_timer "federation-worker" "Morok federation outbound worker" "federation_worker" "12s" "true"
emit_timer "reaper"            "Morok expired-message reaper"      "reaper"            "5min" "true"
emit_timer "dms-reaper"        "Morok dead-man-switch reaper"      "dms_reaper"        "1min" "true"

# Full-scan safety-net (MEDIUM, фрешевий аудит — "reaper масштабується як
# повний filesystem scan"): звичайний morok-reaper.timer вище тепер читає
# прострочені candidates з Redis-індексу (queue.py), не сканує диск —
# швидко, можна запускати кожні 5 хв. Але індекс не бачить orphan-файлів,
# які фізично лежать на диску, але туди ніколи не потрапили (crash між
# write_blob і enqueue; blob'и, записані ДО деплою indexed reaper'а) —
# для них цей окремий, рідкісний (раз на добу) прохід із --full-scan,
# та сама стара rglob()-логіка як безпечна страховка. emit_timer() не
# підтримує передачу CLI-прапорця, тож явний heredoc, як fstrim нижче.
cat > /etc/systemd/system/morok-reaper-fullscan.service <<EOF
[Unit]
Description=Morok blob reaper — full filesystem safety-net scan (orphan recovery)
After=morok-relay.service

[Service]
Type=oneshot
User=${MOROK_USER}
Group=${MOROK_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/.venv/bin/python -m morok_relay.scripts.reaper --full-scan
SyslogIdentifier=morok-reaper-fullscan
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/morok
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
EOF
cat > /etc/systemd/system/morok-reaper-fullscan.timer <<EOF
[Unit]
Description=Schedule: Morok blob reaper full filesystem safety-net scan

[Timer]
OnCalendar=*-*-* 04:15:00
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF

# fstrim: юніти лежали в deploy/, але installer їх НЕ ставив — тобто
# коментар у blob_storage.py про "fstrim-таймер" був порожньою обіцянкою
# навіть на власних релеях. TRIM скорочує вікно життя стертих блобів на
# SSD (гарантії все одно не дає — див. blob_storage.py, LUKS).
cat > /etc/systemd/system/morok-fstrim.service <<EOF
[Unit]
Description=Run fstrim on Morok blob storage filesystem
Documentation=man:fstrim(8)

[Service]
Type=oneshot
ExecStart=/usr/sbin/fstrim -v /
StandardOutput=journal
StandardError=journal
SyslogIdentifier=morok-fstrim
EOF
cat > /etc/systemd/system/morok-fstrim.timer <<EOF
[Unit]
Description=Daily fstrim for SSD secure-delete completeness
Requires=morok-fstrim.service

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true
RandomizedDelaySec=10min
Unit=morok-fstrim.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now morok-relay.service >/dev/null 2>&1
systemctl enable --now morok-federation-worker.timer >/dev/null 2>&1
systemctl enable --now morok-reaper.timer >/dev/null 2>&1
systemctl enable --now morok-reaper-fullscan.timer >/dev/null 2>&1
systemctl enable --now morok-dms-reaper.timer >/dev/null 2>&1
systemctl enable --now morok-fstrim.timer >/dev/null 2>&1
ok "Services enabled and started (incl. fstrim.timer)"

# Give uvicorn a moment, then health-check locally
sleep 3
if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
  ok "Backend responding on 127.0.0.1:8000"
else
  warn "Backend not responding yet — check: journalctl -u morok-relay -n 50"
fi

# ===========================================================================
# 13. nginx (HTTP first, so certbot can complete the challenge)
# ===========================================================================
step "Configuring nginx"
mkdir -p /var/www/certbot
cat > "/etc/nginx/sites-available/morok-${DOMAIN}" <<EOF
upstream morok_backend_${DOMAIN//./_} { server 127.0.0.1:8000; }

# ---------------------------------------------------------------------------
# Tor onion listener.
#
# ЧОМУ ЦЕ ІСНУЄ. Раніше torrc вказував HiddenServicePort прямо на
# 127.0.0.1:8000, тобто Tor ходив в uvicorn МИНАЮЧИ nginx. А застосунок
# довіряє forwarded-заголовкам від 127.0.0.1 (це ж нібито nginx) — отже
# будь-який onion-клієнт міг слати власний X-Real-IP і крутити його на
# кожному запиті: обхід усіх IP-лімітів (auth, admin login, sealed) плюс
# отруєння hashed login audit.
#
# Тепер увесь трафік (clearnet і onion) проходить через nginx, який
# ПЕРЕЗАПИСУЄ ці заголовки — підробити їх ззовні неможливо. X-Morok-Via
# ставить лише nginx; клієнтський заголовок з такою назвою затирається.
server {
    listen 127.0.0.1:8081;
    server_name _;

    # Tor-клієнти не мають осмисленої IP-адреси з нашого боку: усі
    # приходять із loopback. Позначаємо трафік як onion, а бекет для
    # rate-limit беремо спільний (див. get_ip_from_request).
    location / {
        proxy_pass http://morok_backend_${DOMAIN//./_};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto http;
        proxy_set_header X-Morok-Via tor;
    }

    location /ws/ {
        # токен сесії їде в query — не пишемо його в лог
        access_log off;
        proxy_pass http://morok_backend_${DOMAIN//./_};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Morok-Via tor;
        proxy_read_timeout 3600s;
    }
}

# HTTP-ФАЗА НАВМИСНО ПОРОЖНЯ (аудит зовн. №2, П.10). Стара версія
# проксіювала весь API на :80 «щоб certbot пройшов» — але якщо certbot
# падав (DNS не готовий, ліміти Let's Encrypt), installer лише
# попереджав і ЛИШАВ повноцінний API з bearer-сесіями на голому HTTP.
# Тепер до отримання сертифіката порт 80 віддає тільки ACME-челендж і
# /health; решта — 503. Після certbot --redirect цей блок замінюється
# на HTTPS-конфіг із редіректом.
server {
    listen 80;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location = /health {
        proxy_pass http://morok_backend_${DOMAIN//./_};
        proxy_set_header Host \$host;
    }
    location / { return 503; }
}
EOF
ln -sf "/etc/nginx/sites-available/morok-${DOMAIN}" "/etc/nginx/sites-enabled/morok-${DOMAIN}"
nginx -t && systemctl reload nginx
ok "nginx serving ${DOMAIN} on :80"

# ===========================================================================
# 14. TLS certificate
# ===========================================================================
step "Obtaining TLS certificate"
# СХЕМА (аудит зовн. №2, П.10): certonly --webroot замість --nginx.
# --nginx редагував би наш bootstrap-конфіг (де API навмисно 503) і
# скопіював 503 у HTTPS. Натомість: сертифікат окремо, фінальний конфіг
# (80 = ACME+redirect, 443 = повний API) пишемо самі й ДЕТЕРМІНОВАНО.
# Якщо certbot падає — bootstrap лишається, тобто API не світиться на
# HTTP ані секунди; це і є суть фікса.
write_tls_nginx_config() {
  # Фінальний конфіг збираємо З НУЛЯ, включно з tor-listener'ом —
  # жодних sed-правок bootstrap'а, стан детермінований.
  cat > "/etc/nginx/sites-available/morok-${DOMAIN}" <<NGINXEOF
upstream morok_backend_${DOMAIN//./_} {
    server 127.0.0.1:8000;
    keepalive 32;
}

# Tor onion listener — див. коментар у попередній версії: onion-трафік
# мусить іти через nginx, інакше 127.0.0.1 вважається довіреним проксі
# і X-Real-IP можна підробити.
server {
    listen 127.0.0.1:8081;
    location /ws/ {
        access_log off;
        proxy_pass http://morok_backend_${DOMAIN//./_};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Morok-Via tor;
        proxy_read_timeout 3600s;
    }
    location / {
        proxy_pass http://morok_backend_${DOMAIN//./_};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Morok-Via tor;
    }
}

server {
    listen 80;
    server_name ${DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    add_header Strict-Transport-Security "max-age=31536000" always;

    location /ws/ {
        # session token їде в query — не пишемо його в access_log
        access_log off;
        proxy_pass http://morok_backend_${DOMAIN//./_};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        # Явно порожній: clearnet-клієнт не має потрапити в onion-бакет
        proxy_set_header X-Morok-Via "";
        proxy_read_timeout 3600s;
    }

    location / {
        proxy_pass http://morok_backend_${DOMAIN//./_};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Morok-Via "";
    }
}
NGINXEOF
  nginx -t && systemctl reload nginx
}

if curl -fsS --max-time 5 "http://${DOMAIN}/health" >/dev/null 2>&1; then
  if certbot certonly --webroot -w /var/www/certbot -d "$DOMAIN" \
       --non-interactive --agree-tos -m "$EMAIL" \
       --deploy-hook "systemctl reload nginx"; then
    write_tls_nginx_config \
      && ok "HTTPS enabled for ${DOMAIN} (HTTP redirects, API is TLS-only)" \
      || warn "cert obtained but nginx config write failed — check nginx -t"
  else
    warn "certbot failed — API stays LOCKED on :80 (ACME+health only)."
    warn "Fix DNS, then: certbot certonly --webroot -w /var/www/certbot -d ${DOMAIN} -m ${EMAIL} --agree-tos"
    warn "and re-run this installer (re-runnable) to write the TLS config."
  fi
else
  warn "DNS for ${DOMAIN} does not point here yet. API stays LOCKED on :80."
  warn "Add an A-record → this server's IP, then re-run this installer."
fi

# ===========================================================================
# Done — print summary
# ===========================================================================
SERVER_IP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || echo '<this-server-ip>')"

cat <<EOF

${C_GREEN}${C_BOLD}════════════════════════════════════════════════════════════${C_RESET}
${C_GREEN}${C_BOLD}  Morok relay is installed.${C_RESET}
${C_GREEN}${C_BOLD}════════════════════════════════════════════════════════════${C_RESET}

  ${C_BOLD}Domain${C_RESET}        ${DOMAIN}
  ${C_BOLD}Relay pubkey${C_RESET}  ${RELAY_PUB}
  ${C_BOLD}Onion${C_RESET}         ${ONION:-<pending — see note below>}

  ${C_BOLD}${C_YELLOW}Two manual steps remain:${C_RESET}

  ${C_BOLD}1. DNS${C_RESET}
     Point an A-record at this server:
         ${DOMAIN}  →  ${SERVER_IP}
     ${C_DIM}(then, if TLS was skipped above — same command this script${C_RESET}
     ${C_DIM} runs itself, NOT certbot --nginx: that mode rewrites nginx${C_RESET}
     ${C_DIM} config on its own, conflicting with the config this installer${C_RESET}
     ${C_DIM} already wrote deterministically. Re-run this installer instead${C_RESET}
     ${C_DIM} of running certbot manually — it repeats the same certonly step${C_RESET}
     ${C_DIM} and leaves the nginx config untouched by certbot.)${C_RESET}
         certbot certonly --webroot -w /var/www/certbot -d ${DOMAIN} -m ${EMAIL} --agree-tos

  ${C_BOLD}2. Federate${C_RESET} (optional — to talk to other relays)
     Both operators run this on their own relay:

         cd ${INSTALL_DIR}
         sudo -u ${MOROK_USER} .venv/bin/python -m morok_relay.scripts.federate \\
              THEIR_RELAY.example.com

     It prints a FINGERPRINT (eight groups of four digits). Compare it
     with the other operator over a SEPARATE channel — a call, Signal,
     anything but the relays themselves. If it matches, on both sides:

         sudo -u ${MOROK_USER} .venv/bin/python -m morok_relay.scripts.federate \\
              --trust THEIR_RELAY.example.com

     Verifying the fingerprint is not a formality: the handshake proves
     someone holds the key, not that it is the server you meant.

     Your identity, if they ask:
         hostname = ${DOMAIN}
         pubkey   = ${RELAY_PUB}

  ${C_BOLD}Secrets${C_RESET} are in ${INSTALL_DIR}/.env (mode 600).
  ${C_BOLD}${C_RED}Back up that file now${C_RESET} — losing the privkey means losing this
  relay's federation identity permanently.

  ${C_BOLD}Useful commands:${C_RESET}
     systemctl status morok-relay
     journalctl -u morok-relay -f
     systemctl list-timers 'morok-*'

EOF
