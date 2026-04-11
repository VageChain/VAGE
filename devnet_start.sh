#!/bin/bash
# VageChain DevNet Startup Script

cd "$(dirname "$0")/vage"

echo ">>> Building VageChain L1 Node..."
cargo build --release

if [ ! -f target/release/vagechain ]; then
    echo "[x] Node binary not found!"
    exit 1
fi

echo ""
echo "[V] Build complete!"
echo ""
echo "=== Starting VageChain DevNet Node ==="
echo "   RPC endpoint: http://127.0.0.1:8080/rpc"
echo "   Chain ID: vage_devnet_1"
echo ""

target/release/vagechain --config configs/devnet.json --log-level info
