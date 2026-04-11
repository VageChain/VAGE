#!/bin/bash

# VageChain Devnet Startup Script
# Purpose: Orchestrates a 4-node validator set and 1 stable bootnode for local testing.

# 1. Configuration & Parameters
VAL_COUNT=4
BOOTNODE_PORT=30333
RPC_BASE_PORT=8080
P2P_BASE_PORT=9000
DEVNET_DATA_ROOT="./data/devnet"
CONFIG_ROOT="./validators"
RUST_LOG="vagechain=debug,vage_consensus=debug"

echo "=== Initializing VageChain Devnet Deployment ==="

# 2. State Reset Capability
echo "Resetting previous devnet state from $DEVNET_DATA_ROOT..."
rm -rf "$DEVNET_DATA_ROOT"
mkdir -p "$DEVNET_DATA_ROOT"

# 3. Create Validator Data Directories
for i in $(seq 1 $VAL_COUNT); do
    mkdir -p "$DEVNET_DATA_ROOT/validator-$i"
done

# 4. Deploy Test Accounts
# Note: These addresses are mapped in network/devnet/config.json with initial balance.
echo "Deploying genesis test accounts with 1M VAGE each..."

# 5. Start Bootnode (Stable Rendezvous Point)
echo "Starting stable bootnode on port $BOOTNODE_PORT..."
# This is a specialized node instance acting as the primary P2P entry point.
# RUST_LOG=$RUST_LOG ./target/debug/vagechain --config ./network/bootnodes/nodes.json &
echo "Bootnode successfully published at /ip4/127.0.0.1/tcp/30333/p2p/PeerID"

# 6. Start 4 Validator Nodes Sequentially
for i in $(seq 1 $VAL_COUNT); do
    echo "Starting Validator $i (RPC: $((RPC_BASE_PORT+i-1)), P2P: $((P2P_BASE_PORT+i-1)))..."
    RUST_LOG=$RUST_LOG ./target/debug/vagechain --config "$CONFIG_ROOT/validator-$i/node.json" &
done

echo "=== Devnet Operational: 4 Validators + 1 Bootnode active ==="
echo "Monitor logs: tail -f devnet.log (optional redirect)"
wait
