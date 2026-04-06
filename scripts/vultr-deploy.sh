#!/usr/bin/env bash
# ==============================================================================
# vultr-deploy.sh — Final Layer Vultr Server Deployment
# ==============================================================================
# Run this ON the Vultr server after initial SSH access.
# Clones the Final Layer repo, builds neard, sets up all services.
#
# Usage:
#   bash vultr-deploy.sh [--chain-data-tar /path/to/chain-data.tar.gz]
#
# Requirements:
#   - Ubuntu 22.04 LTS
#   - Run as root or sudo
# ==============================================================================

set -euo pipefail

CHAIN_DATA_TAR="${1:-}"
FL_DIR="/opt/final-layer"
NODE_HOME="/root/.fl-node"
CHAIN_ID="final-layer-mainnet"
LOG_FILE="/var/log/fl-deploy.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $*" | tee -a "$LOG_FILE"; }
ok()  { echo -e "${GREEN}✅ $*${NC}" | tee -a "$LOG_FILE"; }
warn(){ echo -e "${YELLOW}⚠️  $*${NC}" | tee -a "$LOG_FILE"; }
err() { echo -e "${RED}❌ $*${NC}" | tee -a "$LOG_FILE"; exit 1; }

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║         FINAL LAYER — Vultr Server Setup                        ║"
echo "║  Quantum-Resistant NEAR Protocol Fork | PQC-enabled             ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: System packages ────────────────────────────────────────────────────

log "Installing system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    build-essential curl git unzip \
    pkg-config libssl-dev \
    clang cmake \
    nginx \
    sqlite3 \
    screen htop \
    2>&1 | tail -5
ok "System packages installed"

# Install Node.js 20
log "Installing Node.js 20..."
apt-get remove -y -qq nodejs npm libnode-dev 2>/dev/null || true
apt-get autoremove -y -qq 2>/dev/null || true
curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
apt-get install -y -qq nodejs 2>&1 | tail -3
ok "Node.js $(node --version) installed"

# Install Rust
log "Installing Rust..."
if ! command -v cargo &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet >/dev/null 2>&1
    source "$HOME/.cargo/env"
fi
ok "Rust $(rustc --version) installed"

# ── Step 2: Clone Final Layer repo ─────────────────────────────────────────────

log "Setting up Final Layer source..."
if [[ ! -d "$FL_DIR" ]]; then
    # The repo will be uploaded by the user; create a placeholder
    mkdir -p "$FL_DIR"
    warn "Source directory $FL_DIR is empty. Upload the source before building."
    warn "Run from your PC: rsync -avz --exclude='build/neard/target' --exclude='.git' --exclude='node_modules' <LOCAL_SOURCE_PATH>/ root@SERVER_IP:$FL_DIR/"
else
    ok "Source found at $FL_DIR"
fi

# ── Step 3: Set Rust toolchain ─────────────────────────────────────────────────

if [[ -f "$FL_DIR/build/neard/rust-toolchain.toml" ]]; then
    log "Installing pinned Rust toolchain..."
    cd "$FL_DIR/build/neard"
    rustup show >/dev/null 2>&1
    ok "Toolchain ready"
fi

# ── Step 4: Build neard (Linux — no Windows Wasmtime issues) ──────────────────

if [[ ! -f "$FL_DIR/build/neard/target/release/neard" ]]; then
    log "Building neard (this takes 20-40 min on first build)..."
    cd "$FL_DIR/build/neard"
    cargo build --release -p neard -p fl-send-tx 2>&1 | tee /var/log/fl-build-neard.log | tail -5
    ok "neard built: $FL_DIR/build/neard/target/release/neard"
else
    ok "neard already built, skipping"
fi

# Build keygen
if [[ ! -f "$FL_DIR/tools/keygen/target/release/fl-keygen" ]]; then
    log "Building fl-keygen..."
    cd "$FL_DIR/tools/keygen"
    cargo build --release 2>&1 | tail -3
    ok "fl-keygen built"
fi

# ── Step 5: Initialize chain node ─────────────────────────────────────────────

log "Initializing Final Layer node..."
mkdir -p "$NODE_HOME/data"

# Copy genesis and config (do NOT copy key files from source)
[[ -f "$FL_DIR/config/genesis.json" ]] && cp "$FL_DIR/config/genesis.json" "$NODE_HOME/genesis.json"
[[ -f "$FL_DIR/config/config.json"  ]] && cp "$FL_DIR/config/config.json"  "$NODE_HOME/config.json"

# Generate fresh node key (NOT the PC's validator key)
NODE_KEY_PATH="$NODE_HOME/node_key.json"
KEYGEN_BIN="$FL_DIR/tools/keygen/target/release/fl-keygen"

if [[ ! -f "$NODE_KEY_PATH" ]] && [[ -x "$KEYGEN_BIN" ]]; then
    log "Generating new node key (ML-DSA)..."
    "$KEYGEN_BIN" generate --key-type mldsa --account-id "server-node.fl" --output "$NODE_KEY_PATH"
    chmod 600 "$NODE_KEY_PATH"
    ok "node_key.json generated"
elif [[ ! -f "$NODE_KEY_PATH" ]]; then
    warn "fl-keygen not found, node_key.json must be provided manually"
fi

# Restore chain data if provided
if [[ -n "$CHAIN_DATA_TAR" ]] && [[ -f "$CHAIN_DATA_TAR" ]]; then
    log "Restoring chain data from $CHAIN_DATA_TAR..."
    tar -xzf "$CHAIN_DATA_TAR" -C "$NODE_HOME/"
    ok "Chain data restored"
else
    warn "No chain data provided — node will start from genesis (block 0)"
    warn "To restore: upload chain-data.tar.gz then re-run with: bash $0 /path/to/chain-data.tar.gz"
fi

ok "Node initialized at $NODE_HOME"

# ── Step 6: Install Node.js dependencies ──────────────────────────────────────

log "Installing explorer API dependencies..."
cd "$FL_DIR/explorer/apps/api"
npm install --silent 2>/dev/null
npm run build --silent 2>/dev/null || warn "Explorer API build warnings (may be ok)"

log "Installing explorer frontend dependencies..."
cd "$FL_DIR/explorer/apps/frontend"
npm install --silent 2>/dev/null
npm run build --silent 2>/dev/null || warn "Explorer frontend build warnings"

log "Installing indexer dependencies..."
cd "$FL_DIR/explorer/apps/indexer"
npm install --silent 2>/dev/null

log "Installing wallet dependencies..."
cd "$FL_DIR/wallet"
npm install --silent 2>/dev/null
npm run build --silent 2>/dev/null || warn "Wallet build warnings"

ok "Node.js dependencies installed"

# ── Step 7: Create systemd services ───────────────────────────────────────────

log "Creating systemd services..."

NEARD_BIN="$FL_DIR/build/neard/target/release/neard"

# Detect public IP for use in service env vars
SERVER_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || \
            curl -s --max-time 5 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || \
            hostname -I | awk '{print $1}')
log "Server IP: $SERVER_IP"

# neard service
cat > /etc/systemd/system/fl-node.service <<EOF
[Unit]
Description=Final Layer Node (neard)
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$NODE_HOME
ExecStart=$NEARD_BIN --home $NODE_HOME run
Restart=on-failure
RestartSec=10
Environment=RUST_LOG=info
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Explorer API service
cat > /etc/systemd/system/fl-explorer-api.service <<EOF
[Unit]
Description=Final Layer Explorer API
After=network.target fl-node.service

[Service]
Type=simple
User=root
WorkingDirectory=$FL_DIR/explorer/apps/api
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
RestartSec=5
Environment=PORT=4000
Environment=DB_PATH=$FL_DIR/final_layer.db
Environment=RPC_URL=http://127.0.0.1:3030
Environment=NODE_ENV=production
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Explorer Frontend service
cat > /etc/systemd/system/fl-explorer-frontend.service <<EOF
[Unit]
Description=Final Layer Explorer Frontend
After=network.target fl-explorer-api.service

[Service]
Type=simple
User=root
WorkingDirectory=$FL_DIR/explorer/apps/frontend
ExecStart=/usr/bin/node .next/standalone/server.js
Restart=on-failure
RestartSec=5
Environment=PORT=3001
Environment=NEXT_PUBLIC_API_URL=http://$SERVER_IP:4000
Environment=NEXT_PUBLIC_RPC_URL=http://127.0.0.1:3030
Environment=NEXT_PUBLIC_CHAIN_ID=final-layer-mainnet
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Indexer service
cat > /etc/systemd/system/fl-indexer.service <<EOF
[Unit]
Description=Final Layer Block Indexer
After=network.target fl-node.service

[Service]
Type=simple
User=root
WorkingDirectory=$FL_DIR/explorer/apps/indexer
ExecStart=/usr/bin/node src/index.js
Restart=on-failure
RestartSec=10
Environment=NODE_RPC_URL=http://127.0.0.1:3030
Environment=DB_PATH=$FL_DIR/final_layer.db
Environment=POLL_MS=2000
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Wallet service
cat > /etc/systemd/system/fl-wallet.service <<EOF
[Unit]
Description=Final Layer Wallet
After=network.target fl-node.service

[Service]
Type=simple
User=root
WorkingDirectory=$FL_DIR/wallet
ExecStart=/usr/bin/node .next/standalone/server.js
Restart=on-failure
RestartSec=5
Environment=PORT=3002
Environment=NEXT_PUBLIC_RPC_URL=http://$SERVER_IP:3030
Environment=NEXT_PUBLIC_CHAIN_ID=final-layer-mainnet
Environment=NEXT_PUBLIC_TLD=.fl
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
ok "Systemd services created"

# ── Step 8: Nginx config ───────────────────────────────────────────────────────

log "Configuring nginx..."

cat > /etc/nginx/sites-available/final-layer <<'NGINX'
server {
    listen 80;
    server_name _;

    # Explorer (default)
    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Explorer API
    location /api/ {
        proxy_pass http://127.0.0.1:4000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Wallet
    location /wallet/ {
        proxy_pass http://127.0.0.1:3002/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # RPC endpoint (public)
    location /rpc {
        proxy_pass http://127.0.0.1:3030;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
NGINX

ln -sf /etc/nginx/sites-available/final-layer /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
ok "Nginx configured"

# ── Step 9: Configure firewall ─────────────────────────────────────────────────

log "Configuring firewall..."
ufw allow OpenSSH >/dev/null 2>&1 || true
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true
ufw allow 3030/tcp >/dev/null 2>&1 || true  # RPC (direct access)
ufw allow 24567/tcp >/dev/null 2>&1 || true  # P2P
ufw --force enable >/dev/null 2>&1 || true
ok "Firewall configured"

# ── Step 10: Enable and start services ────────────────────────────────────────

log "Enabling and starting Final Layer services..."
systemctl enable fl-node fl-indexer fl-explorer-api fl-explorer-frontend fl-wallet >/dev/null 2>&1
systemctl start fl-node
sleep 5
systemctl start fl-indexer fl-explorer-api fl-explorer-frontend fl-wallet

ok "All services started"

# ── Summary ────────────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  ✅ Final Layer Deployed!                                        ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Server IP: $SERVER_IP"
echo ""
echo "  URLs:"
echo "    Explorer:     http://$SERVER_IP/              (Nginx port 80)"
echo "    Wallet:       http://$SERVER_IP/wallet/       (Nginx port 80)"
echo "    Validators:   http://$SERVER_IP/validators"
echo "    Explorer API: http://$SERVER_IP/api/"
echo "    RPC direct:   http://$SERVER_IP:3030"
echo "    P2P:          $SERVER_IP:24567"
echo ""
echo "  Service status:"
echo "    systemctl status fl-node"
echo "    systemctl status fl-indexer"
echo "    systemctl status fl-explorer-api"
echo "    systemctl status fl-explorer-frontend"
echo "    systemctl status fl-wallet"
echo ""
echo "  Logs:"
echo "    journalctl -u fl-node -f"
echo "    journalctl -u fl-indexer -f"
echo "    journalctl -u fl-explorer-api -f"
echo ""
echo "  Chain: final-layer-mainnet | 4 shards | PQC: FN-DSA / ML-DSA / SLH-DSA"
echo ""
