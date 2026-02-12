#!/usr/bin/env bash
set -euo pipefail

color_init() {
  # Use color only for interactive terminals; disable if NO_COLOR is set.
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$'\033[31;1m'
    RESET=$'\033[0m'
  else
    RED=""
    RESET=""
  fi
}

color_init

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"

PORT="${PORT:-3001}"
MODE="auto" # auto|systemd|background
RESET_PASSWORD="0"

usage() {
  cat <<USAGE
Usage: bash deploy.sh [--systemd|--background] [--port 3001] [--reset-password]

Environment:
  PORT=3001
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --systemd) MODE="systemd"; shift ;;
    --background) MODE="background"; shift ;;
    --port) PORT="${2:-3001}"; shift 2 ;;
    --reset-password) RESET_PASSWORD="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

echo "[1/6] Checking Node.js + npm..."
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "node/npm not found. Install Node.js first, then rerun deploy.sh."
  exit 1
fi

echo "[2/6] Installing dependencies..."
npm ci --omit=dev

echo "[3/6] Preparing runtime directories..."
mkdir -p data uploads

SETTINGS_PATH="$APP_DIR/data/settings.json"
PASS_FILE="$APP_DIR/data/initial-admin-password.txt"
PID_FILE="$APP_DIR/data/server.pid"

detect_ip() {
  # Try public IP first (if curl works), then fall back to local IPs.
  if command -v curl >/dev/null 2>&1; then
    local ip
    ip="$(curl -fsS --max-time 2 https://api.ipify.org 2>/dev/null || true)"
    if [ -n "${ip:-}" ]; then
      echo "$ip"
      return
    fi
  fi
  if command -v hostname >/dev/null 2>&1; then
    local ip
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    if [ -n "${ip:-}" ]; then
      echo "$ip"
      return
    fi
  fi
  echo "<your-server-ip>"
}

echo "[4/6] Initial password..."
gen_password() {
  # Avoid pipelines here (pipefail + SIGPIPE can abort the script).
  if command -v openssl >/dev/null 2>&1; then
    local hex
    hex="$(openssl rand -hex 16)" # 32 hex chars
    echo "${hex:0:20}"
    return
  fi
  node -e "console.log(require('crypto').randomBytes(16).toString('hex').slice(0,20))"
}
INIT_PASSWORD=""
if [ "$RESET_PASSWORD" = "1" ]; then
  INIT_PASSWORD="$(gen_password)"
  export INIT_PASSWORD
elif [ -f "$SETTINGS_PATH" ] && node -e "const fs=require('fs');const s=JSON.parse(fs.readFileSync('$SETTINGS_PATH','utf8'));process.exit((s?.auth?.passwordHash && s?.auth?.passwordSalt)?0:1)"; then
  echo "Existing password found in data/settings.json (keeping)."
else
  INIT_PASSWORD="$(gen_password)"
  export INIT_PASSWORD
fi

if [ -n "$INIT_PASSWORD" ]; then
  node <<'NODE'
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const appDir = process.cwd();
const settingsPath = path.join(appDir, 'data', 'settings.json');

let settings = {
  auth: { passwordSalt: '', passwordHash: '' },
  telegram: { botToken: '', chatIds: [] }
};

try {
  if (fs.existsSync(settingsPath)) {
    const raw = fs.readFileSync(settingsPath, 'utf8');
    const parsed = JSON.parse(raw);
    settings = {
      auth: {
        passwordSalt: String(parsed?.auth?.passwordSalt || ''),
        passwordHash: String(parsed?.auth?.passwordHash || '')
      },
      telegram: {
        botToken: String(parsed?.telegram?.botToken || ''),
        chatIds: Array.isArray(parsed?.telegram?.chatIds) ? parsed.telegram.chatIds : []
      }
    };
  }
} catch (_) {}

const initPassword = String(process.env.INIT_PASSWORD || '');
if (!initPassword) process.exit(0);

const salt = crypto.randomBytes(16).toString('hex');
const hash = crypto.scryptSync(initPassword, salt, 64).toString('hex');
settings.auth.passwordSalt = salt;
settings.auth.passwordHash = hash;

fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), 'utf8');
NODE
  printf '%s\n' "$INIT_PASSWORD" > "$PASS_FILE"
  chmod 600 "$PASS_FILE"
  echo "Generated initial password (saved to data/initial-admin-password.txt)."
fi

if [ "$MODE" = "auto" ]; then
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] && [ "$(id -u)" = "0" ]; then
    MODE="systemd"
  else
    MODE="background"
  fi
fi

echo "[5/6] Starting service (mode: $MODE)..."
if [ "$MODE" = "systemd" ]; then
  if [ "$(id -u)" != "0" ]; then
    echo "systemd mode requires root. Re-run as root or use --background."
    exit 1
  fi
  UNIT_PATH="/etc/systemd/system/oracle-panel.service"
  cat > "$UNIT_PATH" <<UNIT
[Unit]
Description=Oracle Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=PORT=$PORT
ExecStart=$(command -v node) server.js
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now oracle-panel.service
else
  if [ -f "$PID_FILE" ]; then
    oldpid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "${oldpid:-}" ] && ps -p "$oldpid" >/dev/null 2>&1; then
      args="$(ps -p "$oldpid" -o args= || true)"
      if echo "$args" | grep -q "node .*server.js"; then
        kill "$oldpid" || true
      fi
    fi
  fi
  PORT="$PORT" setsid node server.js >/tmp/oracle-panel.log 2>&1 < /dev/null &
  echo $! > "$PID_FILE"
fi

echo "[6/6] Done."
IP="$(detect_ip)"
echo "${RED}Login URL:${RESET} http://${IP}:${PORT}/login.html"
if [ -f "$PASS_FILE" ]; then
  echo "Initial password file: $PASS_FILE"
  # User asked to print it. This is only as safe as your server access.
  PASS="$(cat "$PASS_FILE" 2>/dev/null | head -n 1 || true)"
  if [ -n "${PASS:-}" ]; then
    echo "${RED}Initial password:${RESET} $PASS"
  fi
fi
echo "Login and change password in: API Keys -> 后台密码"
