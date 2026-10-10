#!/bin/bash
set -e

DEPLOY_DIR="/opt/kmon-deploy"
API_PORT="19080"
UI_PORT="${KMON_PORT:-32423}"
APP_PASSWORD="${KMON_PASSWORD:-$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16)}"
SESSION_SECRET="$(openssl rand -base64 48)"

echo "======================================"
echo "  KMON NOC Deploy Script"
echo "  UI port:  $UI_PORT"
echo "  API port: $API_PORT"
echo "======================================"

# 1. System dependencies
echo "[1/7] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq curl wget unzip nginx python3 python3-pip build-essential

if ! command -v node &>/dev/null || [[ "$(node -v)" < "v20" ]]; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y nodejs
fi
if ! command -v pnpm &>/dev/null; then
    npm install -g pnpm
fi

# 2. Python dependencies
echo "[2/7] Installing Python packages..."
pip3 install -q aiohttp requests beautifulsoup4 paramiko lxml httpx 2>/dev/null || true

# 3. Copy project files
echo "[3/7] Setting up project..."
mkdir -p "$DEPLOY_DIR"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp -r "$SCRIPT_DIR"/* "$DEPLOY_DIR/" 2>/dev/null || true
mkdir -p "$DEPLOY_DIR/logs" "$DEPLOY_DIR/monitor/data"

# 4. Install Node.js dependencies
echo "[4/7] Installing Node.js dependencies..."
cd "$DEPLOY_DIR"
pnpm install 2>/dev/null || pnpm install --no-frozen-lockfile

# 5. Build API server
echo "[5/7] Building API server..."
cd "$DEPLOY_DIR/artifacts/api-server"
pnpm run build

# 6. Build frontend
echo "[6/7] Building frontend..."
cd "$DEPLOY_DIR"
PORT=8081 BASE_PATH=/ NODE_ENV=production \
    pnpm --filter @workspace/key-monitor run build

# 7. Configure environment
echo "[7/7] Configuring..."
cat > "$DEPLOY_DIR/.env" <<ENV
APP_PASSWORD=$APP_PASSWORD
SESSION_SECRET=$SESSION_SECRET
NODE_ENV=production
COOKIE_SECURE=0
PYTHON_BIN=/usr/bin/python3
PORT=$API_PORT
ENV

# Nginx config
cat > /etc/nginx/sites-available/kmon <<NGINX
server {
    listen $UI_PORT;
    server_name _;
    client_max_body_size 100M;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location ~* \.(env|git|htpasswd|bak|sql|log|conf|ini)$ {
        deny all; return 404;
    }
    location /api {
        proxy_pass http://127.0.0.1:$API_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
    location / {
        root $DEPLOY_DIR/artifacts/key-monitor/dist/public;
        try_files \$uri \$uri/ /index.html;
        expires 1h;
    }
}
NGINX

ln -sf /etc/nginx/sites-available/kmon /etc/nginx/sites-enabled/kmon
nginx -t && systemctl reload nginx

# Systemd service
cat > /etc/systemd/system/kmon-api.service <<SERVICE
[Unit]
Description=KMON API Server
After=network.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User=root
WorkingDirectory=$DEPLOY_DIR/artifacts/api-server
EnvironmentFile=$DEPLOY_DIR/.env
ExecStart=/usr/bin/node --max-old-space-size=4096 dist/index.mjs
Restart=always
RestartSec=5
LimitNOFILE=1048576
StandardOutput=append:$DEPLOY_DIR/logs/kmon-api.log
StandardError=append:$DEPLOY_DIR/logs/kmon-api.log

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable kmon-api
systemctl restart kmon-api

# Verify
sleep 4
STATUS=$(curl -s http://localhost:$API_PORT/api/healthz 2>/dev/null || echo "starting...")
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo "=============================================="
echo "  KMON NOC deployed!"
echo ""
echo "  URL:      http://$SERVER_IP:$UI_PORT"
echo "  Password: $APP_PASSWORD"
echo "  API:      $STATUS"
echo ""
echo "  Logs: journalctl -u kmon-api -f"
echo "=============================================="
