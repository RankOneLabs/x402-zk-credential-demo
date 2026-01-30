# @zk-session/crypto

Cryptographic primitives for ZK session credentials. Must match Noir circuit implementations exactly.

## Primitives

| Primitive | Implementation | Noir Equivalent |
|-----------|----------------|-----------------|
| Pedersen | `@aztec/bb.js` | `std::hash::pedersen_commitment` |
| Poseidon | `poseidon-lite` | `std::hash::poseidon::bn254` |
| Schnorr | `@noble/curves/bn254` | Custom `schnorr.nr` |

## Important Notes

### Pedersen is async

The Barretenberg WASM must initialize before first use:

```typescript
import { pedersenCommit } from '@zk-session/crypto';

// Must await - WASM initializes on first call
const commitment = await pedersenCommit(secret, blinding);
```

### Schnorr is NOT Ethereum-compatible

This uses **BN254 + Poseidon**, not secp256k1 + SHA256. Signatures cannot be verified by Ethereum's `ecrecover`. This is intentional — BN254 is 10-100x cheaper in ZK circuits.

### All values are BN254 scalar field elements

```typescript
const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
```

Use `toField(value)` to reduce values into the field.

### Don't swap implementations

These implementations are chosen to match Noir's stdlib. Using different libraries (e.g., circomlibjs for Poseidon) may produce different outputs and break circuit verification.

## Testing

```bash
npm test
```

Tests include cross-validation against Barretenberg test vectors to ensure TypeScript matches Noir.
