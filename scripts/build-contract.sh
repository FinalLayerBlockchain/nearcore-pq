#!/usr/bin/env bash
# ==============================================================================
# build-contract.sh — Build the fl-test-token WASM contract
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_DIR="$FL_DIR/contracts/fl-test-token"
OUT_DIR="$FL_DIR/contracts/fl-test-token/target/wasm32-unknown-unknown/release"

echo "Building fl-test-token contract..."

# Install wasm target if needed
rustup target add wasm32-unknown-unknown 2>/dev/null || true

cd "$CONTRACT_DIR"
cargo build --release --target wasm32-unknown-unknown 2>&1

WASM="$OUT_DIR/fl_test_token.wasm"
if [[ ! -f "$WASM" ]]; then
    echo "ERROR: WASM not found at $WASM"
    exit 1
fi

# Optimize with wasm-opt if available
if command -v wasm-opt &>/dev/null; then
    wasm-opt -Oz --strip-debug "$WASM" -o "$WASM"
    echo "Optimized with wasm-opt"
fi

SIZE=$(du -sh "$WASM" | cut -f1)
echo "✅ fl_test_token.wasm built: $SIZE"
echo "   Path: $WASM"
