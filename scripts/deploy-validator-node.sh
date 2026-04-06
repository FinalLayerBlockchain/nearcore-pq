#!/usr/bin/env bash
# ==============================================================================
# deploy-validator-node.sh — Deploy a validator-only Final Layer node
# ==============================================================================
# Run ON the Vultr validator server (final-layer or final-layer-validator2).
# Runs neard in validator mode — no explorer, no wallet, no indexer.
#
# Usage:
#   bash deploy-validator-node.sh --validator validator-1.fl
#   bash deploy-validator-node.sh --validator validator-2.fl
#
# Requirements:
#   - Ubuntu 22.04 LTS
#   - Source uploaded to /opt/final-layer (rsync from your PC first)
#   - Run as root
# ==============================================================================

set -euo pipefail

VALIDATOR_ID="${1:-}"
for arg in "$@"; do
  case "$arg" in --validator=*) VALIDATOR_ID="${arg#--validator=}" ;;
    --validator) shift; VALIDATOR_ID="$1" ;;
  esac
done

if [[ -z "$VALIDATOR_ID" ]]; then
  echo "ERROR: --validator <account_id> is required"
  echo "  Example: bash deploy-validator-node.sh --validator validator-1.fl"
  exit 1
fi

FL_DIR="/opt/final-layer"
NODE_HOME="/root/.fl-node"
CHAIN_ID="final-layer-mainnet"
BOOT_NODE_IP="<MAINNET_NODE_IP>"   # final-layer-mainnet (primary node)
BOOT_NODE_P2P_PORT="24567"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $*"; }
ok()  { echo -e "${GREEN}✅ $*${NC}"; }
err() { echo -e "${RED}❌ $*${NC}"; exit 1; }

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Final Layer — Validator Node Setup                              ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo "  Validator ID: $VALIDATOR_ID"
echo "  Boot node:    $BOOT_NODE_IP:$BOOT_NODE_P2P_PORT"
echo ""

# ── Step 1: System packages ────────────────────────────────────────────────────

log "Installing system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential curl git pkg-config libssl-dev clang cmake 2>&1 | tail -3
ok "System packages ready"

# ── Step 2: Rust ───────────────────────────────────────────────────────────────

log "Installing Rust..."
if ! command -v cargo &>/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet >/dev/null 2>&1
  source "$HOME/.cargo/env"
fi
ok "Rust $(rustc --version)"

# ── Step 3: Build neard ────────────────────────────────────────────────────────

if [[ ! -f "$FL_DIR/build/neard/target/release/neard" ]]; then
  log "Building neard (20-40 min first build)..."
  cd "$FL_DIR/build/neard"
  cargo build --release -p neard -p fl-send-tx 2>&1 | tail -5
  ok "neard built"
else
  ok "neard already built"
fi

NEARD_BIN="$FL_DIR/build/neard/target/release/neard"
FL_SEND_TX="$FL_DIR/build/neard/target/release/fl-send-tx"

# Build keygen
if [[ ! -f "$FL_DIR/tools/keygen/target/release/fl-keygen" ]]; then
  log "Building fl-keygen..."
  cd "$FL_DIR/tools/keygen"
  cargo build --release 2>&1 | tail -3
fi
KEYGEN_BIN="$FL_DIR/tools/keygen/target/release/fl-keygen"

# ── Step 4: Node home setup ────────────────────────────────────────────────────

log "Initializing validator node home..."
mkdir -p "$NODE_HOME/data"

[[ -f "$FL_DIR/config/genesis.json" ]] && cp "$FL_DIR/config/genesis.json" "$NODE_HOME/genesis.json"

# Generate fresh node key for P2P (NOT the validator key)
NODE_KEY_PATH="$NODE_HOME/node_key.json"
if [[ ! -f "$NODE_KEY_PATH" ]]; then
  log "Generating node P2P key (ML-DSA)..."
  "$KEYGEN_BIN" generate --key-type mldsa --account-id "${VALIDATOR_ID}-node.fl" --output "$NODE_KEY_PATH"
  chmod 600 "$NODE_KEY_PATH"
  ok "Node P2P key generated"
fi

# Copy the validator's signing key as validator_key.json
# The key must match what was staked on chain
VALIDATOR_KEY_FILE="$FL_DIR/tools/keygen/output/${VALIDATOR_ID//./_}.json"
VALIDATOR_KEY_FNAME=$(echo "$VALIDATOR_ID" | tr '.' '_')
VALIDATOR_KEY_FILE="$FL_DIR/tools/keygen/output/${VALIDATOR_KEY_FNAME}.json"

VALIDATOR_KEY_DEST="$NODE_HOME/validator_key.json"
if [[ -f "$VALIDATOR_KEY_FILE" ]]; then
  cp "$VALIDATOR_KEY_FILE" "$VALIDATOR_KEY_DEST"
  chmod 600 "$VALIDATOR_KEY_DEST"
  ok "Validator key installed: $VALIDATOR_ID"
else
  echo -e "${YELLOW}⚠️  Validator key not found at $VALIDATOR_KEY_FILE${NC}"
  echo "   Upload it manually to $VALIDATOR_KEY_DEST"
fi

# Config.json — point to boot node
cat > "$NODE_HOME/config.json" <<CONFIG
{
  "genesis_file": "genesis.json",
  "validator_key_file": "validator_key.json",
  "node_key_file": "node_key.json",
  "rpc": {
    "addr": "0.0.0.0:3030",
    "cors_allowed_origins": ["*"]
  },
  "network": {
    "addr": "0.0.0.0:24567",
    "boot_nodes": "mldsa_placeholder@$BOOT_NODE_IP:$BOOT_NODE_P2P_PORT",
    "max_num_peers": 40,
    "minimum_outbound_peers": 5
  },
  "chain": {
    "transaction_pool_size": 50000
  },
  "telemetry": {
    "endpoints": []
  },
  "tracked_shards": []
}
CONFIG
ok "Config written (boot node: $BOOT_NODE_IP)"

# ── Step 5: systemd service ────────────────────────────────────────────────────

log "Creating systemd service..."
cat > /etc/systemd/system/fl-validator.service <<EOF
[Unit]
Description=Final Layer Validator Node — $VALIDATOR_ID
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$NODE_HOME
ExecStart=$NEARD_BIN --home $NODE_HOME run
Restart=on-failure
RestartSec=10
Environment=RUST_LOG=info
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable fl-validator
ok "systemd service fl-validator created"

# ── Step 6: Firewall ───────────────────────────────────────────────────────────

log "Configuring firewall..."
ufw allow OpenSSH >/dev/null 2>&1 || true
ufw allow 3030/tcp >/dev/null 2>&1 || true   # RPC
ufw allow 24567/tcp >/dev/null 2>&1 || true  # P2P
ufw --force enable >/dev/null 2>&1 || true
ok "Firewall: SSH + RPC (3030) + P2P (24567)"

# ── Step 7: Start ──────────────────────────────────────────────────────────────

log "Starting validator node..."
systemctl start fl-validator
sleep 5

if systemctl is-active --quiet fl-validator; then
  ok "fl-validator service running"
else
  echo -e "${YELLOW}⚠️  Service may still be starting. Check: journalctl -u fl-validator -f${NC}"
fi

# ── Step 8: Send stake transaction ────────────────────────────────────────────

echo ""
log "Waiting 30s for node to sync before sending stake TX..."
sleep 30

if [[ -f "$VALIDATOR_KEY_DEST" ]]; then
  V_PK=$(grep -o '"public_key":"[^"]*"' "$VALIDATOR_KEY_DEST" | cut -d'"' -f4)
  log "Sending stake transaction for $VALIDATOR_ID (20,000 FLC)..."
  "$FL_SEND_TX" stake \
    --key-file "$VALIDATOR_KEY_DEST" \
    --stake "20000000000000000000000000000" \
    --validator-key "$V_PK" \
    --rpc "http://localhost:3030" 2>&1 || true
  ok "Stake TX submitted for $VALIDATOR_ID"
fi

# ── Summary ────────────────────────────────────────────────────────────────────

SERVER_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  ✅ Validator Node Deployed!                                     ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Validator: $VALIDATOR_ID"
echo "  Server IP: $SERVER_IP"
echo ""
echo "  Status:"
echo "    systemctl status fl-validator"
echo "    journalctl -u fl-validator -f"
echo ""
echo "  Verify staking (from mainnet node):"
echo "    curl -s -X POST http://<MAINNET_NODE_IP>:3030 -H 'Content-Type: application/json' \\"
echo "      -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"validators\",\"params\":[null]}' | grep $VALIDATOR_ID"
echo ""
echo "  Note: Staking takes effect at next epoch boundary."
echo "        Run test-sharding.sh after next epoch to verify."
echo ""
