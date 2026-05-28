#!/usr/bin/env bash
#
# Morok Relay — one-command self-host installer.
#
#   curl -fsSL https://get.morok.app/install.sh | sudo bash
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
PY_MIN_MINOR=11   # require python3.11+

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

DB_PASS="$(openssl rand -hex 24)"
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
KEYS="$(sudo -u "$MOROK_USER" bash -c "cd '$INSTALL_DIR' && .venv/bin/python -m morok_relay.scripts.generate_relay_keypair")"
# Generator prints lines like:
#   MOROK_RELAY_PUBKEY_HEX=<64hex>
#   MOROK_RELAY_PRIVKEY_HEX=<64hex>
# Parse by variable name (robust against extra hex in comments/output).
RELAY_PUB="$(echo "$KEYS"  | grep -oP 'MOROK_RELAY_PUBKEY_HEX=\K[0-9a-fA-F]{64}'  | head -1)"
RELAY_PRIV="$(echo "$KEYS" | grep -oP 'MOROK_RELAY_PRIVKEY_HEX=\K[0-9a-fA-F]{64}' | head -1)"
[[ -n "$RELAY_PUB" && -n "$RELAY_PRIV" ]] || die "Could not parse relay keypair from generator output."
ok "Public key: ${RELAY_PUB}"

# ===========================================================================
# 9. Tor onion service
# ===========================================================================
step "Configuring Tor hidden service"
TORRC="/etc/tor/torrc"
if ! grep -q "morok_relay" "$TORRC" 2>/dev/null; then
  cat >> "$TORRC" <<EOF

# --- Morok relay onion service ---
HiddenServiceDir /var/lib/tor/morok_relay/
HiddenServicePort 80 127.0.0.1:8000
EOF
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
# NOTE: never put a comment '#' on the same line as a secret without a
# leading space — pydantic reads the whole line otherwise. We keep it
# simple: no inline comments next to values.
cat > "$ENV_FILE" <<EOF
MOROK_IS_PRODUCTION=true
MOROK_DEBUG=false
MOROK_RELAY_NAME=${DOMAIN}

MOROK_DB_DSN=postgresql+asyncpg://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}
MOROK_REDIS_URL=redis://localhost:6379/0

MOROK_BLOB_DIR=${BLOB_DIR}

MOROK_RELAY_PUBKEY_HEX=${RELAY_PUB}
MOROK_RELAY_PRIVKEY_HEX=${RELAY_PRIV}
EOF
[[ -n "$ONION" ]] && echo "MOROK_TOR_ONION_ADDRESS=${ONION}" >> "$ENV_FILE"
chown "${MOROK_USER}:${MOROK_USER}" "$ENV_FILE"
chmod 600 "$ENV_FILE"
ok "Wrote $ENV_FILE (mode 600)"

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
ReadWritePaths=${INSTALL_DIR} /var/lib/morok
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

systemctl daemon-reload
systemctl enable --now morok-relay.service >/dev/null 2>&1
systemctl enable --now morok-federation-worker.timer >/dev/null 2>&1
systemctl enable --now morok-reaper.timer >/dev/null 2>&1
systemctl enable --now morok-dms-reaper.timer >/dev/null 2>&1
ok "Services enabled and started"

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

server {
    listen 80;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ { root /var/www/certbot; }

    location /ws/ {
        proxy_pass http://morok_backend_${DOMAIN//./_};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 3600s;
    }

    location / {
        proxy_pass http://morok_backend_${DOMAIN//./_};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
ln -sf "/etc/nginx/sites-available/morok-${DOMAIN}" "/etc/nginx/sites-enabled/morok-${DOMAIN}"
nginx -t && systemctl reload nginx
ok "nginx serving ${DOMAIN} on :80"

# ===========================================================================
# 14. TLS certificate
# ===========================================================================
step "Obtaining TLS certificate"
if curl -fsS --max-time 5 "http://${DOMAIN}/health" >/dev/null 2>&1; then
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect \
    && ok "HTTPS enabled for ${DOMAIN}" \
    || warn "certbot failed — fix DNS, then run: certbot --nginx -d ${DOMAIN}"
else
  warn "DNS for ${DOMAIN} does not point here yet."
  warn "Add an A-record → this server's IP, then run:"
  warn "    certbot --nginx -d ${DOMAIN} --agree-tos -m ${EMAIL} --redirect"
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
     ${C_DIM}(then, if TLS was skipped above:)${C_RESET}
         certbot --nginx -d ${DOMAIN} --agree-tos -m ${EMAIL} --redirect

  ${C_BOLD}2. Federate${C_RESET} (optional — to talk to other relays)
     Exchange pubkeys with an existing relay operator, then on BOTH
     relays insert a federation_peers row. On this relay:

         sudo -u ${MOROK_USER} psql -d ${DB_NAME} -c \\
           "INSERT INTO federation_peers (hostname, pubkey, is_trusted)
            VALUES ('THEIR_RELAY.example.com',
                    decode('THEIR_PUBKEY_HEX','hex'), true);"

     And they add YOURS:
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
