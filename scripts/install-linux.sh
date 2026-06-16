#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "This installer must run as root. Use: sudo bash scripts/install-linux.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

prompt_default() {
    local label="$1"
    local default_value="$2"
    local answer
    read -r -p "$label [$default_value]: " answer
    printf '%s' "${answer:-$default_value}"
}

INSTALL_DIR="$(prompt_default "Install directory" "/opt/ipmi-web")"
DATA_DIR="$(prompt_default "Data directory" "/var/lib/ipmi-web")"
PORT="$(prompt_default "HTTP port" "90")"
SERVICE_NAME="$(prompt_default "Systemd service name" "ipmi-web")"
RUN_USER="$(prompt_default "Run as Linux user" "ipmi-web")"
INSTALL_DEPENDENCIES="$(prompt_default "Install system and Python dependencies automatically? (Y/n)" "Y")"

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "Invalid port: $PORT"
    exit 1
fi

install_packages() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip git ipmitool lm-sensors rsync
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 python3-pip git ipmitool lm_sensors rsync
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3 python3-pip git ipmitool lm_sensors rsync
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --needed --noconfirm python python-pip git ipmitool lm_sensors rsync
    else
        echo "No supported package manager found. Install python3, python3-venv, pip, git, ipmitool, lm-sensors, and rsync manually."
        exit 1
    fi
}

if [[ "$INSTALL_DEPENDENCIES" =~ ^[Nn]$ ]]; then
    echo "Skipping dependency installation. The selected Python environment must already provide the project requirements."
else
    echo "Installing system dependencies..."
    install_packages
fi

if ! id "$RUN_USER" >/dev/null 2>&1; then
    useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin "$RUN_USER"
fi

mkdir -p "$INSTALL_DIR" "$DATA_DIR"
rsync -a \
    --exclude '.venv/' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    --exclude 'app.log*' \
    --exclude 'data.db*' \
    "$SOURCE_DIR"/ "$INSTALL_DIR"/

if [[ "$INSTALL_DEPENDENCIES" =~ ^[Nn]$ ]]; then
    APP_PYTHON="$(command -v python3 || true)"
    if [ -z "$APP_PYTHON" ]; then
        APP_PYTHON="$(command -v python || true)"
    fi
    if [ -z "$APP_PYTHON" ]; then
        echo "Python was not found. Install Python and the project requirements manually, then rerun the installer."
        exit 1
    fi
else
    python3 -m venv "$INSTALL_DIR/.venv"
    APP_PYTHON="$INSTALL_DIR/.venv/bin/python"
    "$APP_PYTHON" -m pip install --upgrade pip
    "$APP_PYTHON" -m pip install -r "$INSTALL_DIR/requirements.txt"
fi

BOOTSTRAP_PASSWORD="$("$APP_PYTHON" -c "import secrets; print(secrets.token_urlsafe(24))")"
BOOTSTRAP_SECRET="$("$APP_PYTHON" -c "import secrets; print(secrets.token_urlsafe(48))")"
REPO_URL="$(git -C "$SOURCE_DIR" config --get remote.origin.url 2>/dev/null || true)"
REPO_BRANCH="$(git -C "$SOURCE_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
CURRENT_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD 2>/dev/null || true)"

export INSTALL_DIR DATA_DIR PORT SERVICE_NAME APP_PYTHON BOOTSTRAP_PASSWORD BOOTSTRAP_SECRET REPO_URL REPO_BRANCH CURRENT_COMMIT
"$APP_PYTHON" - <<'PY'
import json
import os

install_dir = os.environ["INSTALL_DIR"]
data_dir = os.environ["DATA_DIR"]
port = int(os.environ["PORT"])
service_name = os.environ["SERVICE_NAME"]
db_path = os.path.join(data_dir, "data.db")

config = {
    "DATABASE": {
        "path": db_path,
        "retention_days": 7
    },
    "SERVER": {
        "port": port,
        "server_name": "IPMI_WEB"
    },
    "SECURITY": {
        "login_password": os.environ["BOOTSTRAP_PASSWORD"],
        "secret_key": os.environ["BOOTSTRAP_SECRET"],
        "trusted_proxies": []
    }
}

metadata = {
    "service_name": service_name,
    "service_mode": "systemd",
    "install_root": install_dir,
    "data_root": data_dir,
    "db_path": db_path,
    "port": port,
    "python": os.environ["APP_PYTHON"],
    "entrypoint": os.path.join(install_dir, "app.py"),
    "auto_update_mode": "auto",
    "update_channel": "release",
    "update_channels": ["release", "dev"],
    "repo_url": os.environ.get("REPO_URL", ""),
    "branch": os.environ.get("REPO_BRANCH", "") or "main",
    "current_commit": os.environ.get("CURRENT_COMMIT", ""),
    "setup_required": True
}

with open(os.path.join(install_dir, "config.json"), "w", encoding="utf-8") as f:
    json.dump(config, f, ensure_ascii=False, indent=4)
    f.write("\n")
for target_dir in (install_dir, data_dir):
    with open(os.path.join(target_dir, "install.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=4)
        f.write("\n")
PY

chown -R "$RUN_USER":"$RUN_USER" "$INSTALL_DIR" "$DATA_DIR"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=IPMI_WEB
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${APP_PYTHON} ${INSTALL_DIR}/app.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
HOST_IP="${HOST_IP:-127.0.0.1}"

echo
echo "IPMI_WEB is installed and starting."
echo "Open the setup wizard:"
echo "  http://${HOST_IP}:${PORT}/setup"
echo
echo "Service commands:"
echo "  systemctl status ${SERVICE_NAME}"
echo "  journalctl -u ${SERVICE_NAME} -f"
