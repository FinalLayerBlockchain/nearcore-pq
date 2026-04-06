#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Final Layer — Start Script
# Starts all services: PostgreSQL, Redis, Explorer API, Explorer Frontend, Wallet
# ─────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║          FINAL LAYER — Quantum-Resistant Blockchain               ║"
echo "║  Chain ID: final-layer-mainnet  |  TLD: .fl  |  Crypto: PQC      ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

# Check dependencies
check_dep() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: $1 not found. Install it first."; exit 1; }
}

check_dep docker
check_dep node
check_dep npm

echo "▶ Installing explorer dependencies..."
cd "$PROJECT_DIR/explorer"
npm install --prefer-offline 2>&1 | tail -3

echo "▶ Installing wallet dependencies..."
cd "$PROJECT_DIR/wallet"
npm install --prefer-offline 2>&1 | tail -3

echo "▶ Starting infrastructure (PostgreSQL + Redis)..."
cd "$PROJECT_DIR/docker"
docker compose up -d postgres redis
echo "  Waiting for database to be ready..."
sleep 5

echo "▶ Starting Explorer API (port 4000)..."
cd "$PROJECT_DIR/explorer"
npm run dev --workspace=apps/api &
API_PID=$!

echo "▶ Starting Explorer Frontend (port 3001)..."
npm run dev --workspace=apps/frontend &
FRONTEND_PID=$!

echo "▶ Starting Wallet App (port 3000)..."
cd "$PROJECT_DIR/wallet"
npm run dev &
WALLET_PID=$!

echo "▶ Starting Block Indexer..."
cd "$PROJECT_DIR/explorer/apps/indexer"
npm install --prefer-offline 2>&1 | tail -1
npm run dev &
INDEXER_PID=$!

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "✅ Final Layer Services Started"
echo ""
echo "  🔗 Chain RPC:     http://localhost:3030  (start chain node separately)"
echo "  🔍 Explorer:      http://localhost:3001"
echo "  💼 Wallet:        http://localhost:3000"
echo "  📊 Explorer API:  http://localhost:4000"
echo "  📦 Indexer:       running (polls RPC every 2s)"
echo ""
echo "  King.fl wallet address: king.fl"
echo "  To view keys: cat $PROJECT_DIR/tools/keygen/output/king_fl.json"
echo ""
echo "  Press Ctrl+C to stop all services."
echo "═══════════════════════════════════════════════════════════════"

# Wait and cleanup on Ctrl+C
trap "echo ''; echo 'Stopping...'; kill $API_PID $FRONTEND_PID $WALLET_PID $INDEXER_PID 2>/dev/null; cd $PROJECT_DIR/docker && docker compose stop postgres redis; echo 'Done.'" INT TERM
wait
