# GitHub Copilot Instructions for x402-zk-credential-demo

## Project Overview

This is a **proof-of-concept demonstration** of the x402 ZK Session specification. It implements anonymous session credentials for x402 APIs using zero-knowledge proofs.

**⚠️ Important:** This is NOT production-ready code. It's a demo for educational and research purposes.

## Core Philosophy

**Clarity is more important than strict security or performance.** When in doubt:
- Choose readable code over optimized code
- Add explanatory comments for cryptographic operations
- Prefer straightforward implementations over clever tricks
- Document assumptions and limitations clearly

## Repository Structure

```
x402-zk-credential-demo/
├── circuits/           # Noir ZK circuits (97 ACIR opcodes)
├── contracts/          # Solidity contracts (Foundry)
├── packages/
│   ├── crypto/         # TypeScript crypto primitives
│   ├── facilitator/    # Express facilitator server
│   ├── api/            # Express API server with ZK verification
│   ├── cli/            # CLI client with demo script
│   └── e2e/            # End-to-end tests
└── scripts/            # Anvil fork setup, payment demo
```

## Development Guidelines

### 1. TypeScript Development

- **Type Safety:** Use strict TypeScript. Avoid `any` types.
- **Async/Await:** All crypto operations are async (especially `@aztec/bb.js` Pedersen).
- **Error Handling:** Include descriptive error messages for demo/debugging purposes.
- **Testing:** Write tests using Vitest. Match existing test structure in `packages/crypto`.

### 2. Noir Circuit Development

- **Circuit Location:** All circuits are in `circuits/src/`
- **Building:** Use `npm run circuit:build` or `cd circuits && nargo compile`
- **Testing:** Use `npm run circuit:test` or `cd circuits && nargo test`
- **Circuit Complexity:** Target <20K constraints (original design goal). Current implementation: 97 ACIR opcodes which compile to ~4,189 constraints (expression width). ACIR opcodes are higher-level operations; the constraint count determines actual proving cost.
- **Curve:** All operations use BN254 (alt_bn128) curve.

### 3. Cryptographic Primitives

When working with cryptographic code, maintain consistency between TypeScript and Noir:

| Primitive | TypeScript | Noir |
|-----------|------------|------|
| Pedersen | `@aztec/bb.js` | `std::hash::pedersen_commitment` |
| Schnorr | `@noble/curves/bn254` | Custom `schnorr.nr` |
| Poseidon | `poseidon-lite` | `std::hash::poseidon::bn254` |
| EC ops | `@noble/curves/bn254` | `std::embedded_curve_ops` |

**Critical:** TypeScript and Noir implementations must produce identical results. Always cross-validate with test vectors.

### 4. Testing Practices

- **Unit Tests:** Test each cryptographic primitive in isolation
- **Cross-Validation:** Verify TypeScript and Noir implementations match
- **E2E Tests:** Full flow with Anvil + servers (see `packages/e2e`)
- **Test Vectors:** Include known-good values for regression testing

Run tests:
```bash
npm test                                    # All tests
npm test --workspace=@demo/crypto           # Crypto unit tests
npm test --workspace=@demo/e2e              # End-to-end tests
```

### 5. Build System

```bash
npm run build           # Build all packages
npm run lint            # ESLint check
npm run typecheck       # TypeScript type checking
```

**Build Order:** Crypto package must build first (other packages depend on it).

### 6. Documentation Standards

- **Architecture:** Major design decisions go in `ARCHITECTURE.md`
- **Specification:** Protocol details go in `zk-session-spec.md`
- **Code Comments:** Explain WHY, not WHAT. Focus on:
  - Cryptographic assumptions
  - Security properties
  - Privacy guarantees
  - Demo limitations

### 7. Security Considerations

While this is a demo, certain security practices matter:

- **DO:** Validate proof inputs, check expiry times, verify signatures
- **DO:** Document known limitations and attack vectors
- **DON'T:** Add placeholder "TODO: add real security" comments
- **DON'T:** Suggest production deployment in documentation

### 8. Privacy Model

The system has three privacy strategies (see `ARCHITECTURE.md`):
- `max-privacy`: Every request unlinkable
- `time-bucketed`: Unlinkable across time windows (default)
- `max-performance`: All requests linkable

When modifying privacy-related code, ensure all three strategies remain supported.

### 9. Dependencies

**Core Dependencies:**
- `@noir-lang/macaron` - Circuit compilation & proving
- `@aztec/bb.js` - Barretenberg bindings (Pedersen)
- `@noble/curves/bn254` - BN254 curve operations
- `poseidon-lite` - Poseidon hash (BN254)
- `@x402/core`, `@x402/evm` - Payment settlement

**Adding New Dependencies:**
- Justify the addition in PR description
- Prefer well-maintained, audited libraries
- Check compatibility with BN254 curve

### 10. Common Tasks

**Add a new endpoint to API server:**
1. Update `packages/api/src/server.ts`
2. Use `zkSessionMiddleware` for protected endpoints
3. Access verified proof data via `req.zkSession`
4. Update demo script in `packages/cli` if needed

**Modify the circuit:**
1. Edit `circuits/src/main.nr`
2. Run `npm run circuit:build`
3. Run `npm run circuit:test`
4. Update TypeScript types if public inputs change
5. Regenerate verification key if needed

**Add a new cryptographic primitive:**
1. Implement in `packages/crypto/src/`
2. Add Noir version in `circuits/src/`
3. Create test vectors showing equivalence
4. Document in `ARCHITECTURE.md`

### 11. Debugging Tips

**Circuit Debugging:**
- Use `std::println` in Noir for witness debugging
- Run `nargo execute` to see witness values without proving
- Check `circuits/Prover.toml` for test inputs

**Proof Verification Failures:**
- Verify public inputs match exactly (order matters!)
- Check that verification key matches circuit
- Ensure TypeScript and Noir use same hash/commitment implementations

**Payment Issues:**
- Check `.env` configuration (RPC URL, private keys)
- Verify Anvil is running for local tests
- Check USDC contract address matches deployment

### 12. Code Style

- **Formatting:** Use existing code style (no explicit formatter configured)
- **Naming:** 
  - `snake_case` in Noir
  - `camelCase` in TypeScript
  - `SCREAMING_SNAKE_CASE` for constants
- **Comments:** Add context for crypto operations, not obvious code

### 13. What NOT to Do

- ❌ Don't add production-ready features (audit trails, monitoring, etc.)
- ❌ Don't optimize prematurely (clarity > performance)
- ❌ Don't add complex error recovery (fail fast for demos)
- ❌ Don't remove existing warnings about proof-of-concept status
- ❌ Don't suggest deployment to mainnet

### 14. Getting Help

- **Spec Questions:** See `zk-session-spec.md` for protocol details
- **Architecture:** See `ARCHITECTURE.md` for crypto design
- **Noir Help:** https://noir-lang.org/docs
- **x402 Protocol:** https://docs.x402.org

## Example Workflows

### Adding a New Test

```typescript
import { describe, it, expect } from 'vitest';
import { yourFunction } from './your-module';

describe('YourModule', () => {
  it('should do something clearly explained', () => {
    const result = yourFunction(input);
    expect(result).toBe(expectedOutput);
  });
});
```

### Making a Circuit Change

```bash
# 1. Edit circuit
vim circuits/src/main.nr

# 2. Compile
npm run circuit:build

# 3. Test
npm run circuit:test

# 4. Update TypeScript if public inputs changed
vim packages/crypto/src/types.ts

# 5. Run full test suite
npm test
```

## Questions to Ask Before Coding

1. **Does this change make the demo clearer or more confusing?**
2. **Are TypeScript and Noir implementations still consistent?**
3. **Does this maintain the three privacy strategies?**
4. **Is this change documented appropriately?**
5. **Would this work in a real production system, or is it demo-only?**

If you're unsure about any of these, ask for clarification before proceeding.
