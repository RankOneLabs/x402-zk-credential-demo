# x402 ZK Session Demo

> ⚠️ **PROOF OF CONCEPT** - This is a demonstration project for educational and research purposes only. It is NOT production-ready and should NOT be used in any production environment. The cryptographic implementations have not been audited, and the security guarantees are not verified.

**Compliant with [x402 zk-session spec v0.1.0](./zk-session-spec.md)**

Anonymous session credentials for x402 APIs using zero-knowledge proofs.

## Overview

This demo implements a ZK credential system that replaces x402's SIWx identity layer with unlinkable ZK proofs:

- **SIWx proves:** "I am wallet 0xABC" (linkable)
- **ZK Session proves:** "I'm a member of the paid-users set" (unlinkable)

## Architecture (spec §4, §5)

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│ FACILITATOR │      │   CLIENT    │      │   SERVER    │
│  (Issuer)   │      │   (User)    │      │  (Origin)   │
└──────┬──────┘      └──────┬──────┘      └──────┬──────┘
       │                    │                    │
       │                    │ 1. GET /resource   │
       │                    ├───────────────────►│
       │                    │ 2. 402 + zk_session│
       │                    │◄───────────────────┤
       │                    │                    │
       │ 4. settle (tx)     │ 3. Sign EIP-3009   │
       │◄───────────────────┤                    │
       │                    │                    │
       │ 5. credential      │                    │
       │◄───────────────────┤                    │
       │                    │                    │
       │                    │ 6. Authorization:  │
       │                    │    ZKSession proof │
       │                    ├───────────────────►│
       │                    │ 7. 200 OK          │
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
│   ├── facilitator/    # Express facilitator server (payment → credential)
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

# Configure environment
cp .env.example .env
# Edit .env and set your private keys/RPC URLs

# Run crypto tests (49 tests)
npm run test --workspace=@demo/crypto

# Start facilitator server (terminal 1)
npm run facilitator

# Start API server (terminal 2)
npm run api

# Run demo (terminal 3)
npm run demo --workspace=@demo/cli
```

## Current Status

| Component | Status |
|-----------|--------|
| TypeScript crypto (Pedersen, Schnorr, Poseidon) | ✅ Working, 49 tests passing |
| Facilitator server (mock + on-chain payments) | ✅ Working |
| API server (ZK proof verification) | ✅ Working |
| CLI client with demo | ✅ Working |
| Noir circuits | ✅ Working, 97 ACIR opcodes, ~400ms prove time |
| On-chain payment verification | ✅ Working (E2E tested with Anvil) |
| Full ZK proof generation/verification | ✅ Working, 16KB UltraHonk proofs |

## Demo Flow (spec §5.2)

The demo runs with **real payments on local Anvil** (forked from Base Sepolia):

1. **Discovery:** Client requests protected resource → receives 402 with `x402.extensions.zk_session`
2. **Settlement:** Client sends payment + commitment to `/settle` → receives credential
3. **Presentation:** Client makes API requests with `Authorization: ZKSession` header
4. **Verification:** Server verifies ZK proof and applies rate limiting

### 402 Response Format (spec §6)

```json
{
  "x402": {
    "payment_requirements": {
      "amount": "100000",
      "asset": "USDC",
      "facilitator": "http://localhost:3001/settle"
    },
    "extensions": {
      "zk_session": {
        "version": "0.1",
        "schemes": ["pedersen-schnorr-bn254"],
        "facilitator_pubkey": "pedersen-schnorr-bn254:0x04..."
      }
    }
  }
}
```

### Authorization Header (spec §8.1)

```
Authorization: ZKSession pedersen-schnorr-bn254:<base64-proof>
```

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
# Set environment variables in .env
# Required for real payment execution:
# FACILITATOR_PRIVATE_KEY=...
# CHAIN_ID=84532
# RPC_URL=https://sepolia.base.org
# ALLOW_MOCK_PAYMENTS=false

# Or use local Anvil fork
./scripts/start-anvil-fork.sh
# Update .env to point to localhost:8545
```

## Dependencies

- [Noir](https://noir-lang.org/) - ZK circuit language
- [@aztec/bb.js](https://www.npmjs.com/package/@aztec/bb.js) - Barretenberg bindings (Pedersen)
- [@noble/curves](https://www.npmjs.com/package/@noble/curves) - BN254 curve operations
- [poseidon-lite](https://www.npmjs.com/package/poseidon-lite) - Poseidon hash
- [viem](https://viem.sh/) - On-chain payment verification

## License

MIT
