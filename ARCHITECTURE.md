# ZK Session Demo — Technical Architecture

This document describes the cryptographic design, security properties, and implementation details of the ZK Session credential system.

## Table of Contents

1. [Design Goals](#design-goals)
2. [Cryptographic Primitives](#cryptographic-primitives)
3. [Protocol Flow](#protocol-flow)
4. [Circuit Design](#circuit-design)
5. [Privacy Model](#privacy-model)
6. [Security Analysis](#security-analysis)
7. [Implementation Details](#implementation-details)
8. [End-to-End Test](#end-to-end-test)

---

## Design Goals

Replace x402's SIWx (Sign-In-With-X) identity layer with unlinkable ZK proofs:

| Property | SIWx | ZK Session |
|----------|------|------------|
| Authentication | "I am wallet 0xABC" | "I have a valid credential" |
| Linkability | All requests linkable | Configurable per-request |
| Issuer knowledge | Knows user identity | Knows nothing about user secret |
| Rate limiting | By wallet address | By unlinkable origin token |

**Constraint budget target:** <20K constraints for practical client-side proving.

**Actual stats (UltraHonk):**
| Metric | Value |
|--------|-------|
| ACIR opcodes | 97 |
| Proof size | 16 KB |
| Compile time | ~220ms |
| Execute (witness) | ~240ms |
| Prove time | ~400ms |

---

## Cryptographic Primitives

### Curve Selection: BN254

All operations use the BN254 (alt_bn128) curve:

- **Native to Noir:** 10-100x fewer constraints than foreign curves
- **Ethereum precompiles:** `ecAdd` (0x06), `ecMul` (0x07), `ecPairing` (0x08)
- **Two fields:**
  - Base field $\mathbb{F}_p$: Curve point coordinates
  - Scalar field $\mathbb{F}_r$: Where Noir `Field` lives, discrete log exponents

```
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

### Pedersen Commitment

**Purpose:** User commits to `nullifier_seed` without revealing it to the issuer.

**Definition (additive notation):**
$$C = s \cdot G + b \cdot H$$

Where:
- $G, H$ are generator points (Barretenberg's hash-to-curve derived generators)
- $s$ = `nullifier_seed` (user's master secret)
- $b$ = `blinding_factor` (random value for hiding)

**Properties:**
- **Perfectly hiding:** Given $C$, information-theoretically impossible to determine $s$
- **Computationally binding:** User can't open to different value (DL assumption)

**Implementation:**
- **Noir:** `std::hash::pedersen_commitment([secret, blinding])`
- **TypeScript:** `@aztec/bb.js` with matching Barretenberg generators

**Critical security note:** The relationship between $G$ and $H$ must be unknown. Barretenberg's generators are derived via hash-to-curve, ensuring $\log_G(H)$ is computationally infeasible to compute. A naive $H = 2 \cdot G$ would be catastrophically insecure—collisions become trivial:
$$C = s \cdot G + b \cdot (2G) = (s + 2b) \cdot G$$

### Schnorr Signature

**Purpose:** Issuer signs credential attributes. ZK-friendly verification.

**Why Schnorr over ECDSA:**
- ECDSA requires modular inverse in circuit (~20-30K constraints)
- Schnorr is a linear equation (~5-10K constraints)

**Signature generation (issuer, TypeScript):**
```
sign(sk, m):
  k ← random()
  R = k · G
  e = Poseidon(R.x, R.y, pk.x, pk.y, m)
  s = k + e · sk  (mod r)
  return (R, s)
```

**Signature verification (circuit, Noir):**
```
verify(pk, m, R, s):
  e = Poseidon(R.x, R.y, pk.x, pk.y, m)
  assert s · G == R + e · pk
```

**Implementation:**
- **Noir:** Custom `schnorr.nr` using `std::embedded_curve_ops::multi_scalar_mul`
- **TypeScript:** `@noble/curves/bn254` for signing

**Note:** This is NOT Ethereum-compatible Schnorr (which uses secp256k1 + SHA256). This uses BN254 + Poseidon for ZK efficiency.

### Poseidon Hash

**Purpose:** All in-circuit hashing (nullifier derivation, message hashing, Schnorr challenge).

**Why Poseidon:**
- ~300 constraints per hash vs ~25K for SHA256
- Native field arithmetic (no bit decomposition)
- Standard in ZK systems (Semaphore, Tornado Cash, Zcash Orchard)

**Usage:**
```
nullifier = Poseidon(nullifier_seed, origin_id, presentation_index)
msg = Poseidon(service_id, tier, max_presentations, issued_at, expires_at, C.x, C.y)
```

**Implementation:**
- **Noir:** `std::hash::poseidon::bn254::hash_N()`
- **TypeScript:** `poseidon-lite` (BN254 scalar field)
- **String Inputs:** Strings (e.g., `origin_id`) are mapped to field elements via SHA-256 hash-to-field (big-endian mod r).

---

## Protocol Flow

### Issuance Phase (once, after payment)

```
User                                    Issuer (Facilitator)
  |                                       |
  |  1. Generate secrets locally          |
  |     nullifier_seed ← random()         |
  |     blinding_factor ← random()        |
  |     C = Pedersen(seed, blinding)      |
  |                                       |
  |  2. Create Payment Payload            |
  |     (via x402Client / EIP-3009)       |
  |     Sign "transferWithAuthorization"  |
  |                                       |
  |  3. Send settlement request           |
  |  ─────────────────────────────────────>
  |     { payment_payload, C }            |
  |                                       |
  |                    4. Verify & Settle |
  |                       (Submit tx to chain)
  |                    5. Sign credential |
  |                       msg = H(attrs, C)
  |                       sig = Schnorr(sk, msg)
  |                                       |
  |  6. Receive credential                |
  <───────────────────────────────────────
  |     { attrs, C, sig, txHash }         |
  |                                       |
  |  7. Store credential + secrets        |
```

**Privacy guarantee:** Issuer never learns `nullifier_seed`. The commitment is perfectly hiding.
**Payment Guarantee:** Settlement is atomic; credential issued only if transaction succeeds.

### Presentation Phase (per request)

```
User                                    Server
  |                                       |
  |  1. Choose presentation_index         |
  |     (privacy/performance tradeoff)    |
  |                                       |
  |  2. Compute origin_token              |
  |     token = Poseidon(seed, origin, idx)
  |                                       |
  |  3. Generate ZK proof                 |
  |     π = Prove(credential, secrets,    |
  |               origin_id, time)        |
  |                                       |
  |  4. Send authenticated request        |
  |  ─────────────────────────────────────>
  |     { request, π, token, tier }       |
  |                                       |
  |                    5. Verify proof    |
  |                    6. Rate limit by token
  |                    7. Check tier      |
  |                                       |
  |  8. Receive response                  |
  <─────────────────────────────────────── 
```

---

## Circuit Design

### Public Inputs

```noir
service_id: Field        // Which service this proof is for
current_time: Field      // Unix timestamp (or time bucket)
origin_id: Field         // API endpoint identifier
issuer_pubkey_x: Field   // Issuer's Schnorr public key (x coordinate)
issuer_pubkey_y: Field   // Issuer's Schnorr public key (y coordinate)
```

### Private Inputs (Witness)

```noir
// Credential fields (signed by issuer)
cred_tier: Field
cred_max_presentations: Field
cred_issued_at: Field
cred_expires_at: Field
cred_commitment: Point   // C = Pedersen(seed, blinding)

// Signature
sig_r: Point
sig_s: Field

// User secrets (never revealed)
nullifier_seed: Field
blinding_factor: Field
presentation_index: Field
```

### Public Outputs

```noir
origin_token: Field      // Rate-limiting token (unlinkable)
tier: Field              // Access tier for authorization
```

### Constraints

1. **Pedersen opening:** Verify commitment opens correctly
   ```noir
   assert C == pedersen_commitment([nullifier_seed, blinding_factor])
   ```

2. **Service binding:** Credential is for this service
   ```noir
   assert cred_service_id == service_id
   ```

3. **Expiry check:** Credential not expired
   ```noir
   assert cred_expires_at >= current_time
   ```

4. **Presentation bound:** Index within allowed range
   ```noir
   assert presentation_index < cred_max_presentations
   ```

5. **Schnorr verification:** Issuer signature is valid
   ```noir
   msg = poseidon_hash(service_id, tier, ..., C.x, C.y)
   e = poseidon_hash(sig_r.x, sig_r.y, pk.x, pk.y, msg)
   assert sig_s · G == sig_r + e · pk
   ```

6. **Token derivation:** Compute unlinkable rate-limit token
   ```noir
   origin_token = poseidon_hash(nullifier_seed, origin_id, presentation_index)
   ```

### Actual Circuit Statistics

Using UltraHonk proving system (BN254):

| Metric | Value |
|--------|-------|
| ACIR opcodes | 97 |
| Brillig opcodes | 0 |
| Expression Width | 4,189 |
| Proof size | 16,256 bytes (~16 KB) |

**Timing (native `bb prove`):**
- Compile: ~220ms
- Execute (witness generation): ~240ms  
- Prove (ZK proof generation): ~400ms

**Note:** The 16KB proof size is fixed overhead from UltraHonk's universal setup—small circuits pay the same fixed cost as larger ones. For header-based transport, consider Groth16 (~200 bytes) or use request body.

---

## Privacy Model

### Client-Controlled Linkability

The `presentation_index` field gives clients control over the privacy/performance tradeoff:

```
origin_token = Poseidon(nullifier_seed, origin_id, presentation_index)
```

- **Same index → Same token:** Requests are linkable (but proof can be cached)
- **Different index → Different token:** Requests are unlinkable (new proof required)

### Privacy Strategies

| Strategy | `presentation_index` | Privacy | Performance |
|----------|---------------------|---------|-------------|
| `max-privacy` | Always increment | Every request unlinkable | ~100ms per request |
| `time-bucketed` | `floor(time / window)` | Unlinkable across windows | One proof per window |
| `max-performance` | Always 0 | All requests linkable | Cached proof reused |

**Default:** `time-bucketed` with 5-minute windows (production) or 60-second (demo).

### Privacy Budget

With `max_presentations = 1000`:
- **max-privacy:** 1000 unlinkable requests, then credential exhausted
- **time-bucketed (5 min):** ~83 hours of unlinkable sessions
- **max-performance:** Unlimited requests, fully linkable

### What the Issuer Learns

| Data | Issuer Knowledge |
|------|------------------|
| `nullifier_seed` | ❌ Hidden by Pedersen commitment |
| Payment source | ✅ Sees payment proof (wallet address) |
| Credential usage | ❌ Cannot link issuance to presentations |

### What the Server Learns

| Data | Server Knowledge |
|------|------------------|
| User identity | ❌ Only sees unlinkable origin_token |
| Credential issuer | ✅ Knows issuer public key |
| Access tier | ✅ Revealed for authorization |
| Request patterns | ⚠️ Linkable within same presentation_index |

---

## Security Analysis

### Threat Model

1. **Malicious Issuer:** Cannot learn user secrets (Pedersen is perfectly hiding)
2. **Malicious Server:** Cannot link requests across presentation indices
3. **Colluding Issuer + Server:** Cannot link issuance to presentation (commitment hides seed)

### Attack Vectors

**Replay attacks:** Mitigated by:
- Proof bound to `origin_id` (can't reuse across endpoints)
- Proof bound to `current_time` or `time_bucket` (expires naturally)
- Rate limiting still applies (replayed requests count against token)

**Proof theft:** If attacker steals a cached proof:
- Can only use for the same origin
- Shares rate limit with legitimate user
- Time-bucketed proofs expire quickly

**Credential theft:** If attacker steals full credential:
- Can impersonate user until expiry
- Mitigation: Short expiry times, secure storage

### Binding Properties

| Binding | Mechanism |
|---------|-----------|
| Proof → Service | `service_id` in public inputs |
| Proof → Time | `current_time` in public inputs |
| Proof → Origin | `origin_id` in public inputs |
| Credential → User | Schnorr signature over commitment |

---

## Implementation Details

### Package Structure

```
packages/
├── crypto/           # Shared cryptographic primitives
│   ├── pedersen.ts   # @aztec/bb.js Pedersen commitment
│   ├── schnorr.ts    # @noble/curves BN254 signing
│   ├── poseidon.ts   # poseidon-lite wrapper (BN254)
│   └── utils.ts      # Field conversions, hex encoding
├── issuer/           # Credential issuance server
│   ├── server.ts     # Express server, /issue endpoint
│   ├── issuer.ts     # CredentialIssuer class
│   └── payment-verifier.ts  # On-chain USDC transfer verification
├── api/              # Protected API server
│   ├── server.ts     # Express server with protected endpoints
│   ├── middleware.ts # ZkSessionMiddleware (402 discovery, verification)
│   ├── verifier.ts   # ZkVerifier (UltraHonk proof verification)
│   └── ratelimit.ts  # Per-token rate limiting
├── cli/              # Client SDK
│   └── client.ts     # ZkSessionClient (credential + proof management)
├── e2e/              # End-to-end tests
│   └── tests/flow.test.ts  # Full flow with Anvil + servers
circuits/             # Noir ZK circuits
├── src/main.nr       # Main circuit (97 ACIR opcodes)
├── src/schnorr.nr    # Schnorr signature verification
├── src/pedersen.nr   # Pedersen commitment verification
└── src/utils.nr      # Field comparison helpers
contracts/            # Solidity contracts (Foundry)
└── src/MockUSDC.sol  # ERC20 mock for testing
```

### Dependency Map

| Primitive | TypeScript | Noir |
|-----------|------------|------|
| Pedersen | `@aztec/bb.js` | `std::hash::pedersen_commitment` |
| Schnorr sign | `@noble/curves/bn254` | — |
| Schnorr verify | — | Custom (`schnorr.nr`) |
| Poseidon | `poseidon-lite` | `std::hash::poseidon::bn254` |
| EC ops | `@noble/curves/bn254` | `std::embedded_curve_ops` |
| Payment | `@x402/core`, `@x402/evm` | — |

### Async Considerations

The `@aztec/bb.js` Pedersen implementation requires WASM initialization:

```typescript
import { pedersenCommit, initBB } from './pedersen';

// Must init before first use
await initBB();

// Now async
const commitment = await pedersenCommit(secret, blinding);
```

### Test Vectors

All primitives have cross-validated test vectors ensuring Noir circuits match TypeScript:

```typescript
// Pedersen: commit([1n, 1n]) must equal this exact point
const expected = "0x2f7a8f9a6c96a...";

// Poseidon: hash matches circomlibjs reference
// Schnorr: sign in TS, verify in Noir
```

### On-Chain Payment Verification

Facilitator uses `@x402/evm` to execute settlements:

```typescript
// Active Settlement (EIP-3009)
const evmScheme = new ExactEvmScheme(signer);
const result = await evmScheme.settle(paymentPayload, requirements);
// result.transaction contains the tx hash
```

Supported chains: Base Sepolia (84532), with Anvil fork for local development.

Supported chains: Base Sepolia (84532), with Anvil fork for local development.

---

## End-to-End Test

The E2E test (`packages/e2e/tests/flow.test.ts`) validates the complete x402 ZK Session flow against real infrastructure:

### Test Infrastructure

```
┌─────────────────────────────────────────────────────────────────────┐
│  Local Anvil (Chain 31337)                                          │
│  └── MockUSDC Contract (0x5fbd...aa3)                              │
├─────────────────────────────────────────────────────────────────────┤
│  Issuer Server (localhost:3001)                                     │
│  └── PaymentVerifier → Reads on-chain USDC transfers               │
│  └── CredentialIssuer → Signs credentials with Schnorr             │
├─────────────────────────────────────────────────────────────────────┤
│  API Server (localhost:3002)                                        │
│  └── ZkSessionMiddleware → Verifies UltraHonk proofs               │
│  └── Rate limiter → Tracks per origin_token                        │
└─────────────────────────────────────────────────────────────────────┘
```

### Test Phases

1. **Deploy MockUSDC** (~1s)
   - Starts local Anvil instance
   - Deploys ERC20 mock contract via Forge

2. **Start Servers**
   - Issuer with on-chain payment verification enabled
   - API with ZK proof verification enabled

3. **Full Flow** (~11s)
   ```
   Discovery (402) → Mint USDC → Pay Issuer → Get Credential → 
   Generate ZK Proof → Verify Proof → Access Granted
   ```

### What Gets Validated

| Step | Validation |
|------|------------|
| Discovery | Returns 402 with `issuerUrl`, `price`, `serviceId` |
| Payment | On-chain USDC transfer verified via event logs |
| Issuance | Schnorr signature verified client-side |
| Proof Gen | 16KB UltraHonk proof, 7 public inputs |
| Verification | Real `bb.js` verification (not mocked) |
| Rate Limiting | Origin token tracked, headers set |

### Running the E2E Test

```bash
# Full test suite (149 tests: 144 passed, 5 skipped)
npm test

# E2E only
npm test --workspace=@demo/e2e

# With verbose output
DEBUG=true npm test --workspace=@demo/e2e
```

### Sample Output

```
✓ should deploy MockUSDC (1067ms)
✓ should start Issuer and API servers
✓ should execute full flow: Discovery -> Mint -> Pay -> Issue -> Verify (10935ms)

Test Files  1 passed (1)
     Tests  3 passed (3)
```

### Key Log Messages

```
[PaymentVerifier] Verified: $1 USDC from 0x70997970...
[Issuer] Returning signature: { r: {...}, s: '0x2e68c1b7...' }
[Client] Proof size: 16256 bytes, 7 public inputs
[ZkVerifier] Initialized successfully
[ZkSession] Proof verified for tier 1, origin: 2f6170692f77686f...
```

---

## References

- [Noir Language Documentation](https://noir-lang.org/docs)
- [Barretenberg (bb.js)](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg/ts)
- [BN254 Curve](https://eips.ethereum.org/EIPS/eip-196)
- [Poseidon Hash](https://eprint.iacr.org/2019/458)
- [Schnorr Signatures](https://en.wikipedia.org/wiki/Schnorr_signature)
