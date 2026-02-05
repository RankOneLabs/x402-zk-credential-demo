#!/bin/bash
# Start local Anvil chain forked from Base Sepolia
# This gives us real USDC contract for testing

set -e

# Base Sepolia RPC (public endpoint)
BASE_SEPOLIA_RPC="${BASE_SEPOLIA_RPC:-https://sepolia.base.org}"

echo "Starting Anvil forked from Base Sepolia..."
echo "  Fork RPC: $BASE_SEPOLIA_RPC"
echo "  Local RPC: http://localhost:8545"
echo "  Chain ID: 84532 (Base Sepolia)"
echo ""
echo "Test accounts (each has 10000 ETH):"
echo "  Account 0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
echo "  Private Key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
echo ""

# Start anvil with Base Sepolia fork
anvil \
  --fork-url "$BASE_SEPOLIA_RPC" \
  --chain-id 84532 \
  --block-time 1 \
  --accounts 10 \
  --balance 10000 \
  --host 0.0.0.0 \
  --port 8545
