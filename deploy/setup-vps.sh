#!/bin/bash
# ========================================
# MS TELECOM - Hotspot System
# VPS Deployment Script
# ========================================
# Usage: ssh root@your-vps "bash -s" < deploy/setup-vps.sh

set -e

APP_DIR="/opt/hotspot-system"
REPO_URL="https://github.com/MS-Telecom/hotspot-system.git"
SERVICE_NAME="hotspot-system"

echo "=== MS TELECOM - Hotspot System VPS Setup ==="

# 1. Install Node.js 22 if not present
if ! command -v node &> /dev/null; then
  echo "Installing Node.js 22..."
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
fi

echo "Node.js version: $(node -v)"

# 2. Clone or update repository
if [ -d "$APP_DIR" ]; then
  echo "Updating existing installation..."
  cd "$APP_DIR"
  git pull origin main
else
  echo "Cloning repository..."
  git clone "$REPO_URL" "$APP_DIR"
  cd "$APP_DIR"
fi

# 3. Install dependencies
echo "Installing dependencies..."
npm install --production

# 4. Create .env if not exists
if [ ! -f "$APP_DIR/.env" ]; then
  echo "Creating .env from example..."
  cp "$APP_DIR/.env.example" "$APP_DIR/.env"
  echo ">>> IMPORTANT: Edit $APP_DIR/.env with your actual credentials!"
fi

# 5. Create systemd service
echo "Creating systemd service..."
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=MS TELECOM Hotspot System API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/node backend/server.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production
EnvironmentFile=${APP_DIR}/.env

[Install]
WantedBy=multi-user.target
EOF

# 6. Enable and start service
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl restart ${SERVICE_NAME}

echo ""
echo "=== Deployment Complete ==="
echo "Service status: $(systemctl is-active ${SERVICE_NAME})"
echo "Logs: journalctl -u ${SERVICE_NAME} -f"
echo ""
echo "Next steps:"
echo "  1. Edit /opt/hotspot-system/.env with your credentials"
echo "  2. Restart: systemctl restart ${SERVICE_NAME}"
echo "  3. Configure nginx reverse proxy (see deploy/nginx.conf)"
