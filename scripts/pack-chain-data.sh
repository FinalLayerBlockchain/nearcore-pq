#!/usr/bin/env bash
# ==============================================================================
# pack-chain-data.sh — Package chain data for secure transfer to Vultr
# ==============================================================================
# Creates a tar.gz of the chain state (blocks/state DB) WITHOUT any private keys.
#
# Usage:
#   bash scripts/pack-chain-data.sh
#
# Output:
#   /tmp/fl-chain-data.tar.gz  — chain data only, safe to transfer
# ==============================================================================

set -euo pipefail

NODE_HOME="${HOME}/.fl-node"
OUTPUT="/tmp/fl-chain-data.tar.gz"

echo "Packaging chain data (no private keys)..."
echo "Source: $NODE_HOME"
echo "Output: $OUTPUT"
echo ""

# Pack only the data directory (blocks/state), NOT key files
# Explicitly exclude validator_key.json and node_key.json
tar -czf "$OUTPUT" \
    --exclude="$NODE_HOME/validator_key.json" \
    --exclude="$NODE_HOME/node_key.json" \
    -C "$(dirname "$NODE_HOME")" \
    "$(basename "$NODE_HOME")"

SIZE=$(du -sh "$OUTPUT" | cut -f1)
echo "✅ Packed $SIZE → $OUTPUT"
echo ""
echo "Transfer to server:"
echo "  scp $OUTPUT root@SERVER_IP:/tmp/"
echo ""
echo "Then on server:"
echo "  bash /opt/final-layer/scripts/vultr-deploy.sh /tmp/fl-chain-data.tar.gz"
echo ""
echo "⚠️  Verify the archive has NO key files:"
echo "  tar -tzf $OUTPUT | grep key"
