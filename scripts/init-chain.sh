#!/usr/bin/env bash
# ==============================================================================
# init-chain.sh — Final Layer Node Initialization Script
# ==============================================================================
#
# This script initializes a Final Layer node data directory at ~/.fl-node/
#
# What it does:
#   1. Creates the node data directory at ~/.fl-node/
#   2. Copies config.json and genesis.json from the project config/ directory
#   3. Generates a node_key.json using ML-DSA Dilithium3 (NIST FIPS 204)
#   4. Outputs usage instructions
#
# Usage:
#   ./scripts/init-chain.sh [--home <dir>]
#
# Options:
#   --home <dir>   Override the default node data directory (default: ~/.fl-node)
#
# Requirements:
#   - The Final Layer keygen tool must be built:
#       cargo build --release --manifest-path tools/keygen/Cargo.toml
#   - Run from the project root (final-layer/)
#
# ==============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_DIR="${PROJECT_ROOT}/config"

# Default node home directory
NODE_HOME="${HOME}/.fl-node"

CHAIN_ID="final-layer-mainnet"
VERSION="1.0.0-final-layer"

# ── Parse arguments ───────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --home)
            NODE_HOME="$2"
            shift 2
            ;;
        --home=*)
            NODE_HOME="${1#--home=}"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--home <dir>]"
            echo ""
            echo "Initialize a Final Layer node at the given home directory."
            echo ""
            echo "Options:"
            echo "  --home <dir>   Node data directory (default: ~/.fl-node)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run '$0 --help' for usage."
            exit 1
            ;;
    esac
done

# ── Banner ────────────────────────────────────────────────────────────────────

echo "============================================================"
echo "  Final Layer Node Initialization"
echo "  Chain:   ${CHAIN_ID}"
echo "  Version: ${VERSION}"
echo "  Home:    ${NODE_HOME}"
echo "============================================================"
echo ""

# ── Step 1: Create node data directory ───────────────────────────────────────

echo "[1/4] Creating node data directory..."
mkdir -p "${NODE_HOME}"
mkdir -p "${NODE_HOME}/data"
echo "  Created: ${NODE_HOME}"

# ── Step 2: Copy config.json ──────────────────────────────────────────────────

echo ""
echo "[2/4] Copying configuration files..."

CONFIG_SRC="${CONFIG_DIR}/config.json"
CONFIG_DST="${NODE_HOME}/config.json"

if [[ -f "${CONFIG_SRC}" ]]; then
    if [[ -f "${CONFIG_DST}" ]]; then
        echo "  config.json already exists at ${CONFIG_DST}, skipping."
        echo "  (Remove it manually if you want to re-initialize.)"
    else
        cp "${CONFIG_SRC}" "${CONFIG_DST}"
        echo "  Copied: config.json"
    fi
else
    echo "  WARNING: ${CONFIG_SRC} not found."
    echo "  Copy it manually to ${CONFIG_DST} before starting the node."
fi

GENESIS_SRC="${CONFIG_DIR}/genesis.json"
GENESIS_DST="${NODE_HOME}/genesis.json"

if [[ -f "${GENESIS_SRC}" ]]; then
    if [[ -f "${GENESIS_DST}" ]]; then
        echo "  genesis.json already exists at ${GENESIS_DST}, skipping."
    else
        cp "${GENESIS_SRC}" "${GENESIS_DST}"
        echo "  Copied: genesis.json"
    fi
else
    echo "  WARNING: ${GENESIS_SRC} not found."
    echo "  Copy it manually to ${GENESIS_DST} before starting the node."
fi

# ── Step 3: Generate node key ─────────────────────────────────────────────────

echo ""
echo "[3/4] Generating node key (ML-DSA Dilithium3 / NIST FIPS 204)..."

NODE_KEY_PATH="${NODE_HOME}/node_key.json"
KEYGEN_BIN="${PROJECT_ROOT}/tools/keygen/target/release/fl-keygen"

if [[ -f "${NODE_KEY_PATH}" ]]; then
    echo "  node_key.json already exists at ${NODE_KEY_PATH}, skipping."
    echo "  (Remove it manually to generate a new node key.)"
else
    if [[ -x "${KEYGEN_BIN}" ]]; then
        # Use the Final Layer keygen tool to generate an ML-DSA node key
        echo "  Generating ML-DSA keypair using keygen tool..."
        "${KEYGEN_BIN}" generate \
            --key-type mldsa \
            --account-id "node.fl" \
            --output "${NODE_KEY_PATH}"
        echo "  Generated: node_key.json (ML-DSA Dilithium3)"
    else
        echo "  WARNING: keygen binary not found at ${KEYGEN_BIN}"
        echo "  Build it first with:"
        echo "    cargo build --release --manifest-path tools/keygen/Cargo.toml"
        echo ""
        echo "  Generating a placeholder node_key.json..."
        # Write a placeholder that can be replaced
        cat > "${NODE_KEY_PATH}" << 'PLACEHOLDER'
{
  "account_id": "node.fl",
  "public_key": "mldsa:PLACEHOLDER_REPLACE_WITH_REAL_KEY",
  "secret_key": "mldsa:PLACEHOLDER_REPLACE_WITH_REAL_KEY",
  "note": "Run: tools/keygen/target/release/keygen generate --key-type mldsa --account-id node.fl --output ~/.fl-node/node_key.json"
}
PLACEHOLDER
        echo "  Created placeholder: node_key.json"
        echo "  IMPORTANT: Replace with a real ML-DSA key before connecting to mainnet!"
    fi
fi

# ── Step 4: Set file permissions ──────────────────────────────────────────────

echo ""
echo "[4/4] Setting file permissions..."

# Restrict access to key files (Unix only)
if [[ "$(uname -s)" != "MINGW"* ]] && [[ "$(uname -s)" != "CYGWIN"* ]]; then
    chmod 600 "${NODE_KEY_PATH}" 2>/dev/null || true
    chmod 644 "${NODE_HOME}/config.json"  2>/dev/null || true
    chmod 644 "${NODE_HOME}/genesis.json" 2>/dev/null || true
    echo "  Set permissions: node_key.json (600), config.json (644), genesis.json (644)"
else
    echo "  Skipping Unix permissions (Windows detected)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  Final Layer node initialized."
echo ""
echo "  Node directory: ${NODE_HOME}"
echo "  Files created:"

for f in config.json genesis.json node_key.json; do
    fpath="${NODE_HOME}/${f}"
    if [[ -f "${fpath}" ]]; then
        size=$(wc -c < "${fpath}" 2>/dev/null || echo "?")
        echo "    ${f} (${size} bytes)"
    fi
done

echo ""
echo "  IMPORTANT: Before connecting to mainnet, verify:"
echo "    1. node_key.json contains a real ML-DSA key (not PLACEHOLDER)"
echo "    2. genesis.json validator keys are populated (not PLACEHOLDER)"
echo "    3. Your validator key file is in ${NODE_HOME}/validator_key.json"
echo ""
echo "  Run ./scripts/start.sh to begin."
echo "============================================================"
