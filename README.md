# x402 ZK Credential Demo

> ⚠️ **PROOF OF CONCEPT** - This is a demonstration project for educational and research purposes only. It is NOT production-ready and should NOT be used in any production environment. The cryptographic implementations have not been audited, and the security guarantees are not verified.

**Compliant with [x402 zk-credential spec v0.1.0](./zk-credential-spec.md)**

Anonymous credentials for x402 APIs using zero-knowledge proofs.

## Overview

This demo implements a ZK credential system that replaces x402's SIWx identity layer with unlinkable ZK proofs:

- **SIWx proves:** "I am wallet 0xABC" (linkable)
- **ZK Credential proves:** "I'm a member of the paid-users set" (unlinkable)

## Architecture (spec §4, §5)

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│ FACILITATOR │      │   SERVER    │      │   CLIENT    │
│  (Issuer)   │      │  (Origin)   │      │   (User)    │
└──────┬──────┘      └──────┬──────┘      └──────┬──────┘
       │                    │                    │
       │                    │◄───────────────────┤ 1. GET /resource
      │                    │───────────────────►│ 2. 402 + zk-credential
       │                    │                    │
       │                    │◄───────────────────┤ 3. Sign EIP-3009
       │◄───────────────────┤ (proxy settle)     │
       │ 4. settle (tx)     │                    │
       │ 5. credential      │                    │
       │───────────────────►│                    │
       │                    │───────────────────►│ 6. 200 OK + credential
       │                    │                    │
      │                    │◄───────────────────┤ 7. POST /resource
      │                    │                    │    Body: ZK proof
       │                    │───────────────────►│ 8. 200 OK
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

## Circuit Statistics (UltraHonk)

This implementation uses the **BN254** curve with Noir's UltraHonk backend:

| Metric | Value |
|--------|-------|
| ACIR opcodes | **97** |
| Proof size | ~16 KB |
| Proving time | ~400ms |
| Verification | ~240ms |

## Core Dependencies

| Component | Library | Purpose |
|-----------|---------|---------|
| Payment | `@x402/core`, `@x402/evm` | Settlement & Verification |
| ZK Proofs | `@noir-lang/macaron` | Circuit compilation & proving |
| Elliptic Curve | `@noble/curves/bn254` | Schnorr signing & verification |
| Commitments | `@aztec/bb.js` | Pedersen commitments |

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

1. **Discovery:** Client requests protected resource → receives 402 with `extensions["zk-credential"]`
2. **Settlement:** Client sends payment + commitment (body) → receives credential
3. **Presentation:** Client presents ZK proof by POSTing it in the request body (`x402_zk_credential` envelope)
4. **Verification:** Server verifies ZK proof and applies rate limiting

### 402 Response Format (spec §7)

```json
{
  "x402Version": 2,
  "accepts": [
    {
      "scheme": "exact",
      "network": "eip155:8453",
      "amount": "100000",
      "payTo": "0x1234...",
      "asset": "0xABCD..."
    }
  ],
  "extensions": {
    "zk-credential": {
      "info": {
        "version": "0.1.0",
        "credential_suites": ["pedersen-schnorr-poseidon-ultrahonk"],
        "issuer_suite": "pedersen-schnorr-poseidon-ultrahonk",
        "issuer_pubkey": "BAAB...",
        "max_credential_ttl": 86400,
        "service_id": "k7VzM_xR9bQ2h1nPfEjw"
      },
      "schema": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
          "commitment": {
            "type": "string",
            "description": "Suite-typed commitment: '<suite>:<base64url(point)>'"
          }
        }
      }
    }
  }
}
```

### Proof Identity Body (spec §6.3)

```json
{
  "x402_zk_credential": {
    "version": "0.1.0",
    "suite": "pedersen-schnorr-poseidon-ultrahonk",
    "issuer_pubkey": "BAAB...",
    "proof": "<base64-proof>",
    "current_time": 1707004800,
    "public_outputs": {
      "origin_token": "0x...",
      "tier": 1
    }
  }
}
```

## Privacy Budget

Clients control the privacy/performance tradeoff via `identity_index`:

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

To enable real USDC payment verification (Base Sepolia), configure the following in your `.env` file (see `.env.example`):

```bash
# Facilitator's private key for executing EIP-3009 transfers
FACILITATOR_PRIVATE_KEY=0x...

# Chain configuration
CHAIN_ID=84532
RPC_URL=https://sepolia.base.org

# Disable mock payments for production
ALLOW_MOCK_PAYMENTS=false
```

For local development, you can use an Anvil fork:

```bash
./scripts/start-anvil-fork.sh
# Then set RPC_URL=http://localhost:8545 in your .env
```

## Dependencies

- [Noir](https://noir-lang.org/) - ZK circuit language
- [@aztec/bb.js](https://www.npmjs.com/package/@aztec/bb.js) - Barretenberg bindings (Pedersen)
- [@noble/curves](https://www.npmjs.com/package/@noble/curves) - BN254 curve operations
- [poseidon-lite](https://www.npmjs.com/package/poseidon-lite) - Poseidon hash
- [viem](https://viem.sh/) - On-chain payment verification

## License

MIT
