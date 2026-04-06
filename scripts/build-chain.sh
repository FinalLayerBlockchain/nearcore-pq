#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Final Layer — Build Chain Node
# Builds the nearcore-based node binary and supporting tools from the
# pre-patched build tree at build/neard/.
#
# Binaries produced:
#   build/neard/target/release/neard         — chain node daemon
#   build/neard/target/release/fl-send-tx    — transaction sender CLI
#   tools/keygen/target/release/keygen       — PQC key generator
#
# This takes ~30-60 minutes on first build (Rust compile + PQC crates).
# ─────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${FL_DIR}/build/neard"
KEYGEN_DIR="${FL_DIR}/tools/keygen"

echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║          FINAL LAYER — Chain Build                                ║"
echo "║  Quantum-resistant NEAR Protocol fork (PQC-enabled)               ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

# ── Preflight checks ──────────────────────────────────────────────────────────

if ! command -v cargo &>/dev/null; then
  echo "ERROR: cargo not found. Install Rust from https://rustup.rs/"
  exit 1
fi

if [ ! -d "${BUILD_DIR}" ]; then
  echo "ERROR: Build tree not found at ${BUILD_DIR}"
  echo "Expected the pre-patched nearcore directory to exist there."
  exit 1
fi

echo "Build directory: ${BUILD_DIR}"
echo "Rust version:    $(rustc --version)"
echo ""

# ── Step 1: Build neard (chain node) ─────────────────────────────────────────

echo "▶ Building neard (chain node)..."
echo "  This takes 30-60 minutes on first build. Coffee time ☕"
echo ""

cd "${BUILD_DIR}"
cargo build --release -p neard 2>&1 | tee "${FL_DIR}/build-neard.log"

NEARD_BIN="${BUILD_DIR}/target/release/neard"
if [ ! -f "${NEARD_BIN}" ] && [ ! -f "${NEARD_BIN}.exe" ]; then
  echo "ERROR: neard binary not found after build. Check build-neard.log"
  exit 1
fi
echo ""
echo "✅ neard built: ${NEARD_BIN}"

# ── Step 2: Build fl-send-tx (transaction sender CLI) ────────────────────────

echo ""
echo "▶ Building fl-send-tx (transaction sender)..."
cargo build --release -p fl-send-tx 2>&1 | tee -a "${FL_DIR}/build-neard.log"

FL_SEND_TX_BIN="${BUILD_DIR}/target/release/fl-send-tx"
if [ ! -f "${FL_SEND_TX_BIN}" ] && [ ! -f "${FL_SEND_TX_BIN}.exe" ]; then
  echo "ERROR: fl-send-tx binary not found after build. Check build-neard.log"
  exit 1
fi
echo "✅ fl-send-tx built: ${FL_SEND_TX_BIN}"

# ── Step 3: Build keygen tool ─────────────────────────────────────────────────

echo ""
echo "▶ Building fl-keygen (PQC key generator)..."
cd "${KEYGEN_DIR}"
cargo build --release 2>&1 | tee "${FL_DIR}/build-keygen.log"

KEYGEN_BIN="${KEYGEN_DIR}/target/release/keygen"
if [ ! -f "${KEYGEN_BIN}" ] && [ ! -f "${KEYGEN_BIN}.exe" ]; then
  # Cargo.toml name is "fl-keygen" so binary might be fl-keygen
  KEYGEN_BIN="${KEYGEN_DIR}/target/release/fl-keygen"
fi
echo "✅ keygen built: ${KEYGEN_BIN}"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║  ✅ Build complete!                                               ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Binaries:"
echo "  ${BUILD_DIR}/target/release/neard"
echo "  ${BUILD_DIR}/target/release/fl-send-tx"
echo "  ${KEYGEN_DIR}/target/release/fl-keygen"
echo ""
echo "Next steps:"
echo "  1. ./scripts/init-chain.sh    — Initialize chain data directory"
echo "  2. ./scripts/start.sh         — Start all Final Layer services"
echo ""
