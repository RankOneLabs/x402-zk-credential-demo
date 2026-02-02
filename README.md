# x402 ZK Session Demo

> ⚠️ **PROOF OF CONCEPT** - This is a demonstration project for educational and research purposes only. It is NOT production-ready and should NOT be used in any production environment. The cryptographic implementations have not been audited, and the security guarantees are not verified.

Anonymous session credentials for x402 APIs using zero-knowledge proofs.

## Overview

This demo implements a ZK credential system that replaces x402's SIWx identity layer with unlinkable ZK proofs:

- **SIWx proves:** "I am wallet 0xABC" (linkable)
- **ZK Session proves:** "I'm a member of the paid-users set" (unlinkable)

## Architecture

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   ISSUER    │      │    USER     │      │   SERVER    │
│  (Service)  │      │  (Client)   │      │  (Origin)   │
└──────┬──────┘      └──────┬──────┘      └──────┬──────┘
       │                    │                    │
       │  ISSUANCE: x402 payment → credential   │
       │◄───────────────────┤                    │
       ├───────────────────►│                    │
       │                    │                    │
       │  PRESENTATION: ZK proof → access       │
       │                    ├───────────────────►│
       │                    │◄───────────────────┤
```

## Project Structure

```
x402-zk-session-demo/
├── circuits/           # Noir ZK circuit (97 ACIR opcodes)
│   └── src/
│       ├── main.nr     # Main circuit entry point
│       ├── pedersen.nr # Pedersen commitment (wraps stdlib)
│       ├── schnorr.nr  # Schnorr verification (BN254 + Poseidon)
│       └── utils.nr    # Field comparison helpers
├── contracts/          # Solidity contracts (Foundry)
│   └── src/MockUSDC.sol
├── packages/
│   ├── crypto/         # TypeScript crypto primitives (matches circuits)
│   ├── issuer/         # Express issuer server (payment → credential)
│   ├── api/            # Express API server with ZK verification
│   ├── cli/            # CLI client with demo script
│   └── e2e/            # End-to-end tests (Anvil + full flow)
└── scripts/            # Anvil fork setup, payment demo
```

## Quick Start

```bash
# Clone with submodules (for Foundry contracts)
git clone --recursive <repo-url>
# Or if already cloned:
git submodule update --init --recursive

# Install dependencies
npm install

# Build all packages
npm run build

# Run crypto tests (49 tests)
npm run test --workspace=@demo/crypto

# Start issuer server (terminal 1)
npm run issuer

# Start API server (terminal 2)
npm run api

# Run demo (terminal 3)
npm run demo --workspace=@demo/cli
```

## Current Status

| Component | Status |
|-----------|--------|
| TypeScript crypto (Pedersen, Schnorr, Poseidon) | ✅ Working, 49 tests passing |
| Issuer server (mock + on-chain payments) | ✅ Working |
| API server (ZK proof verification) | ✅ Working |
| CLI client with demo | ✅ Working |
| Noir circuits | ✅ Working, 97 ACIR opcodes, ~400ms prove time |
| On-chain payment verification | ✅ Working (E2E tested with Anvil) |
| Full ZK proof generation/verification | ✅ Working, 16KB UltraHonk proofs |

## Demo Flow

The demo runs with **real payments on local Anvil** (forked from Base Sepolia):

1. Start Anvil fork: `./scripts/start-anvil-fork.sh`
2. Client generates secrets locally (`nullifier_seed`, `blinding_factor`)
3. Client computes Pedersen commitment (hides secrets from issuer)
4. Client sends USDC payment + commitment to issuer
5. Issuer verifies on-chain payment and returns signed credential
6. Client makes authenticated API requests
7. API server verifies proofs and applies rate limiting

## Privacy Budget

Clients control the privacy/performance tradeoff via `presentation_index`:

| Strategy | Privacy | Performance |
|----------|---------|-------------|
| `max-privacy` | Every request unlinkable | New proof each request |
| `time-bucketed` | Unlinkable across 5-min windows | One proof per window |
| `max-performance` | All requests linkable | Cached proof reused |

Default: `time-bucketed` with 60-second windows (demo) / 5-minute (production).

## Cryptography

| Primitive | Implementation | Notes |
|-----------|----------------|-------|
| Pedersen commitment | `@aztec/bb.js` | Matches Noir's `std::hash::pedersen_commitment` |
| Schnorr signatures | Custom (BN254 + Poseidon) | ZK-optimized, not Ethereum-compatible |
| Poseidon hash | `poseidon-lite` | BN254 scalar field |
| Curve operations | `@noble/curves/bn254` | For Schnorr signing |

## On-Chain Payment Verification

To enable real USDC payment verification (Base Sepolia):

```bash
# Set environment variables
export RECIPIENT_ADDRESS=0xYourPaymentAddress
export CHAIN_ID=84532
export RPC_URL=https://sepolia.base.org
export ALLOW_MOCK_PAYMENTS=false

# Or use local Anvil fork
./scripts/start-anvil-fork.sh
export RPC_URL=http://localhost:8545
```

## Dependencies

- [Noir](https://noir-lang.org/) - ZK circuit language
- [@aztec/bb.js](https://www.npmjs.com/package/@aztec/bb.js) - Barretenberg bindings (Pedersen)
- [@noble/curves](https://www.npmjs.com/package/@noble/curves) - BN254 curve operations
- [poseidon-lite](https://www.npmjs.com/package/poseidon-lite) - Poseidon hash
- [viem](https://viem.sh/) - On-chain payment verification

## License

MIT
