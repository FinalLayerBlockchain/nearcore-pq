#!/usr/bin/env bash
# ==============================================================================
# deploy-contract.sh — Deploy fl-test-token contract to Final Layer
# ==============================================================================
# Deploys the FLTT token contract to token.fl using king.fl as the deployer.
# Must be run AFTER the chain node is running.
#
# Usage (local):
#   bash scripts/deploy-contract.sh [--rpc http://localhost:3030]
#
# Usage (Vultr):
#   bash scripts/deploy-contract.sh --rpc http://<MAINNET_NODE_IP>:3030
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

RPC_URL="${1:-http://localhost:3030}"
# Allow --rpc flag
for arg in "$@"; do
  case "$arg" in
    --rpc=*) RPC_URL="${arg#--rpc=}" ;;
  esac
done
shift $((OPTIND - 1)) 2>/dev/null || true

# On Vultr, paths differ
if [[ -d "/opt/final-layer" ]]; then
  FL_DIR="/opt/final-layer"
fi

NEARD_BIN="$FL_DIR/build/neard/target/release/neard"
FL_SEND_TX="$FL_DIR/build/neard/target/release/fl-send-tx"
WASM_PATH="$FL_DIR/contracts/fl-test-token/target/wasm32-unknown-unknown/release/fl_test_token.wasm"
KING_KEY="$FL_DIR/tools/keygen/output/king_fl.json"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Final Layer — Deploy fl-test-token Contract                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  RPC:     $RPC_URL"
echo "  Contract: token.fl"
echo "  Deployer: king.fl"
echo ""

# ── Preflight ──────────────────────────────────────────────────────────────────

[[ -f "$WASM_PATH" ]] || { echo "ERROR: WASM not found. Run: bash scripts/build-contract.sh"; exit 1; }
[[ -f "$FL_SEND_TX" ]] || [[ -f "${FL_SEND_TX}.exe" ]] || { echo "ERROR: fl-send-tx not found. Run: bash scripts/build-chain.sh"; exit 1; }
[[ -f "$KING_KEY" ]] || { echo "ERROR: king.fl key not found at $KING_KEY"; exit 1; }

# Use .exe on Windows
[[ -f "${FL_SEND_TX}.exe" ]] && FL_SEND_TX="${FL_SEND_TX}.exe"

# ── Wait for node ─────────────────────────────────────────────────────────────

echo "Waiting for RPC node at $RPC_URL..."
for i in $(seq 1 30); do
  if curl -sf -X POST "$RPC_URL" \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"status","params":[]}' >/dev/null 2>&1; then
    echo "  Node is reachable ✓"
    break
  fi
  echo "  Attempt $i/30 — waiting 5s..."
  sleep 5
done

# ── Deploy contract ───────────────────────────────────────────────────────────

WASM_SIZE=$(du -sh "$WASM_PATH" | cut -f1)
echo "Deploying contract ($WASM_SIZE) to token.fl..."

"$FL_SEND_TX" deploy \
  --key-file    "$KING_KEY" \
  --receiver    "token.fl" \
  --wasm        "$WASM_PATH" \
  --init-method "new" \
  --init-args   '{"owner_id":"king.fl","name":"Final Layer Test Token","symbol":"FLTT","decimals":24,"description":"Official demo token on Final Layer mainnet — quantum-resistant NEAR Protocol fork","initial_supply":"1000000000000000000000000000000"}' \
  --rpc         "$RPC_URL"

echo ""
echo "✅ Contract deployed to token.fl"
echo ""
echo "View at explorer: http://<MAINNET_NODE_IP>/contracts/token.fl"
echo ""

# ── Verify deployment ─────────────────────────────────────────────────────────

echo "Verifying deployment — calling ft_metadata()..."
sleep 3

"$FL_SEND_TX" view-call \
  --account   "token.fl" \
  --method    "ft_metadata" \
  --args      '{}' \
  --rpc       "$RPC_URL" 2>/dev/null || echo "  (view-call not yet supported — verify via RPC manually)"

echo ""
echo "Manual verification:"
echo "  curl -s -X POST $RPC_URL -H 'Content-Type: application/json' \\"
echo "    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"call_function\",\"finality\":\"final\",\"account_id\":\"token.fl\",\"method_name\":\"ft_metadata\",\"args_base64\":\"e30=\"}}'"
