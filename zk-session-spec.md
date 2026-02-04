# x402 Extension: ZK Session Credentials

**Extension ID:** `zk-session`  
**Version:** 0.1.0  
**Status:** Draft  
**Last Updated:** 2026-02-03

---

## 1. Overview

This extension enables **pay-once, redeem-many** access to x402-protected resources using privacy-preserving session credentials proved in zero knowledge.

**Design intent:** Keep x402 payment semantics intact. Payment uses standard x402 mechanisms. This extension changes only post-payment redemption, allowing clients to make multiple requests without re-paying and without creating linkable per-user sessions.

---

## 2. Goals

1. **One payment, multiple requests** — Reduce cost and latency of repeating settlement operations for many API calls.

2. **Unlinkable redemption** — After payment, subsequent requests are unlinkable to the payer identity by the server, beyond unavoidable network metadata.

3. **Minimal protocol disturbance** — Works as an optional extension layered on existing x402 flow. HTTP 402 remains "Payment Required."

4. **Short-lived sessions** — Session credentials are time-bounded and usage-bounded.

---

## 3. Non-Goals

- Replace x402 payments with "proof-only access"
- Provide anonymity against global network observers
- Prescribe a specific SNARK system — only the proof statement and wire format matter

---

## 4. Entities

| Entity | Role |
|--------|------|
| **Client** | Requests protected resource, performs x402 payment, proves credential possession |
| **Server** | Protected resource server. Verifies ZK proofs for access control |
| **Facilitator** | x402 intermediary that verifies/settles payment AND issues session credentials |

The **Facilitator is the Issuer**. This follows naturally from x402's architecture:
- Client already sends payment to facilitator
- Facilitator already returns payment confirmation
- Credential issuance piggybacks on this existing flow
- No additional trust assumptions required

---

## 5. Flow Overview

### 5.1 Standard x402 (reference)

```
1. Client → Server:      GET /resource
2. Server → Client:      402 Payment Required (includes facilitator info)
3. Client → Facilitator: Payment
4. Facilitator → Client: Payment confirmation
5. Client → Server:      GET /resource + X-PAYMENT
6. Server → Client:      200 OK
```

### 5.2 x402 + zk-session

```
1. Client → Server:      GET /resource
2. Server → Client:      402 + zk_session extension advertised
3. Client → Facilitator: Payment + commitment
4. Facilitator → Client: Payment confirmation + signed credential
5. Client → Server:      GET /resource + Authorization: ZKSession <proof>
6. Server → Client:      200 OK

(Steps 5-6 repeat until credential expires or max_presentations reached)
```

The key change: Step 3-4 bundles credential issuance with payment confirmation. The facilitator:
- Verifies/settles payment (existing role)
- Signs and returns session credential (new role)

---

## 6. Extension Advertisement

When returning `402 Payment Required`, servers supporting zk-session include:

```json
{
  "x402": {
    "payment_requirements": { /* standard x402 */ },
    "extensions": {
      "zk_session": {
        "version": "0.1",
        "schemes": ["pedersen-schnorr-bn254"],
        "facilitator_pubkey": "pedersen-schnorr-bn254:0x04abc..."
      }
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `version` | Spec version |
| `schemes` | Supported cryptographic schemes (see §12) |
| `facilitator_pubkey` | Scheme-prefixed public key for credential verification |

The `credential_endpoint` is implicit - credentials are issued by the facilitator as part of the payment flow. Clients that don't support zk-session ignore the extension and use standard x402.

---

## 7. Credential Issuance

### 7.1 Client Preparation

Before payment, client generates locally (never sent to facilitator):
- `nullifier_seed` — random secret
- `blinding_factor` — random blinding value

Client computes:
- `commitment = Commit(nullifier_seed, blinding_factor)` — hiding commitment

### 7.2 Payment Request with Commitment

Client includes commitment in the x402 payment request to facilitator:

```json
{
  "payment": { /* standard x402 payment */ },
  "zk_session": {
    "commitment": "pedersen-schnorr-bn254:0x..."
  }
}
```

### 7.3 Payment Response with Credential

Facilitator returns credential alongside payment confirmation:

```json
{
  "payment_receipt": { /* standard x402 receipt */ },
  "zk_session": {
    "credential": {
      "scheme": "pedersen-schnorr-bn254",
      "service_id": "0xabc123...",
      "tier": 1,
      "max_presentations": 1000,
      "issued_at": 1706918400,
      "expires_at": 1707004800,
      "commitment": "0x...",
      "signature": "0x..."
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `service_id` | Identifies the service/API |
| `tier` | Access level (0, 1, 2, ...) — derived from payment amount |
| `max_presentations` | Maximum proof presentations allowed |
| `issued_at` | Unix timestamp of issuance |
| `expires_at` | Unix timestamp of expiration |
| `commitment` | Client's commitment (echoed back) |
| `signature` | Facilitator signature over all fields |

**Facilitator MUST NOT** store or log commitment-to-payment mappings beyond operational needs.

---

## 8. Credential Presentation

### 8.1 Transport

Clients present credentials via the `Authorization` header:

```
Authorization: ZKSession <scheme>:<base64-proof>
```

Example:
```
GET /api/resource HTTP/1.1
Host: api.example.com
Authorization: ZKSession pedersen-schnorr-bn254:eyJwcm9vZiI6...
```

### 8.2 Proof Public Inputs

The server provides or derives these values for verification:

| Input | Source |
|-------|--------|
| `service_id` | Server configuration |
| `current_time` | Server clock (unix timestamp) |
| `origin_id` | `hash(request_path)` or server-assigned |
| `facilitator_pubkey` | Server configuration |

**Origin ID normalization (RECOMMENDED):** Servers SHOULD define `origin_id` over a canonical form (method + normalized path template + host) to avoid accidental linkability or bypass via trivial path variations.

### 8.3 Proof Public Outputs

The proof produces:

| Output | Purpose |
|--------|---------|
| `origin_token` | Unlinkable rate-limiting token |
| `tier` | Access level for authorization |

---

## 9. Proof Statement

The ZK proof MUST prove:

1. **Commitment opening** — Prover knows `(nullifier_seed, blinding_factor)` that open the credential's commitment

2. **Valid signature** — Issuer's signature over `(service_id, tier, max_presentations, issued_at, expires_at, commitment)` is valid

3. **Service binding** — Credential's `service_id` matches public input

4. **Not expired** — `expires_at >= current_time`

5. **Presentation bound** — `presentation_index < max_presentations`

6. **Origin token derivation** — `origin_token = hash(nullifier_seed, origin_id, presentation_index)`

The proof outputs `(origin_token, tier)` publicly.

---

## 10. Rate Limiting and Replay Prevention

### 10.1 Origin Token

```
origin_token = hash(nullifier_seed, origin_id, presentation_index)
```

Properties:
- **Deterministic** — Same inputs produce same token
- **Origin-bound** — Different endpoints produce different tokens
- **Unlinkable across origins** — Tokens for `/api/foo` and `/api/bar` are unlinkable
- **Client-controlled linkability** — Reusing `presentation_index` produces same token (linkable); incrementing produces different token (unlinkable)

### 10.2 Server Behavior

Servers track `origin_token` usage:
- New token → allow, start tracking
- Known token within window → increment count, check limit
- Token exceeds limit → reject (429)

Servers SHOULD:
- Use short rate-limit windows
- Prune expired token entries periodically
- Bound memory by enforcing credential expiry

### 10.3 Client Behavior

Clients manage `presentation_index`:
- **Maximum privacy:** Increment for every request (different token each time)
- **Stable identity per origin:** Reuse same index per origin (enables per-origin rate limiting)
- **Hybrid:** Increment within session, reset across sessions

---

## 11. Verification Flow

Server steps:

1. Parse `Authorization` header for `ZKSession` scheme
2. If missing → `401` with `WWW-Authenticate: ZKSession`
3. Extract scheme prefix from proof
4. If unsupported scheme → `400 unsupported_zk_scheme`
5. Construct public inputs: `(service_id, current_time, origin_id, facilitator_pubkey)`
6. Verify proof
7. If invalid → `401 invalid_zk_proof`
8. Extract outputs: `(origin_token, tier)`
9. Check rate limit for `origin_token`
10. If exceeded → `429 rate_limited`
11. Check `tier` meets endpoint requirement
12. If insufficient → `403 tier_insufficient`
13. Allow request

---

## 12. Scheme Registry

Schemes define the complete cryptographic stack. The scheme identifier is an opaque label; this registry defines what each label means.

| Scheme ID | Commitment | Signature | Hash | Proof System | Curve |
|-----------|------------|-----------|------|--------------|-------|
| `pedersen-schnorr-bn254` | Pedersen | Schnorr | Poseidon | UltraHonk/Groth16 | BN254 |

New schemes are registered by updating this specification.

### 12.1 Scheme: `pedersen-schnorr-bn254`

Reference implementation: `x402-zk-session-noir`

| Component | Specification |
|-----------|---------------|
| Curve | BN254 (alt_bn128) |
| Commitment | Pedersen with standard generators |
| Signature | Schnorr (R, s) |
| Hash | Poseidon (t=3, RF=8, RP=57) |
| Proof system | Implementation choice (UltraHonk, Groth16) |

Encoding details defined in reference implementation.

---

## 13. Error Responses

| Code | HTTP | Meaning |
|------|------|---------|
| `unsupported_zk_scheme` | 400 | Scheme not supported |
| `invalid_zk_proof` | 401 | Proof verification failed |
| `proof_expired` | 401 | Credential expired |
| `tier_insufficient` | 403 | Tier below requirement |
| `rate_limited` | 429 | Origin token rate limited |
| `presentations_exhausted` | 429 | max_presentations reached |

Missing credentials:
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: ZKSession schemes="pedersen-schnorr-bn254"
```

---

## 14. Security Properties

### 14.1 Required Properties

| Property | Requirement |
|----------|-------------|
| **Issuer blindness** | Issuer MUST NOT learn `nullifier_seed` from commitment |
| **Unforgeability** | Credentials MUST NOT be forgeable without issuer key |
| **Credential hiding** | Proof MUST NOT reveal which credential is used |
| **Origin unlinkability** | Different `origin_id` MUST produce unlinkable tokens |
| **Public verifiability** | Proof MUST be verifiable without issuer interaction |

### 14.2 What This Provides

- Server verifies "paid + authorized" without learning stable client identifier
- Repeated requests don't require repeated payment artifacts
- Different API endpoints see unlinkable tokens

### 14.3 What This Does Not Prevent

- Correlation via IP, TLS fingerprint, timing, cookies
- Timing correlation at issuance (credential issued immediately after payment links the two)
- Credential theft (mitigate with short expiry)

---

## 15. Security Considerations

| Threat | Mitigation |
|--------|------------|
| Issuer key compromise | Key rotation, short credential expiry |
| Credential theft | Short expiry, `max_presentations` limit |
| Replay attacks | `presentation_index` in token derivation |
| Time manipulation | Server provides `current_time` as public input |
| DoS via verification | Rate limiting, proof size limits |

---

## 16. Privacy Considerations

| Property | Status | Notes |
|----------|--------|-------|
| Payment-credential unlinkability | Partial | Timing correlation possible at issuance |
| Credential-request unlinkability | ✓ | ZK proof hides credential |
| Cross-origin unlinkability | ✓ | Different `origin_id` → different token |
| Within-origin linkability | Configurable | Client controls via `presentation_index` |

**Timing correlation mitigation (RECOMMENDED):**
- Batch credential requests
- Delay between payment and credential request
- Use anonymous network for issuance

---

## 17. Compatibility

- First access remains standard x402
- Extension is optional, negotiated via `extensions.zk_session`
- Non-implementing clients/servers remain compatible with base x402
- Multiple schemes can coexist; client picks from server's `schemes` list

**x402 semantics note (normative):**
- A server MUST continue to use `402 Payment Required` when neither a valid x402 payment nor a valid `Authorization: ZKSession ...` proof is present.
- zk-session changes the *post-payment redemption path* only; it does not redefine what a `402` means.

---

## 18. Conformance

An implementation conforms to this specification if it:

1. Advertises support via `extensions.zk_session` in 402 responses
2. Issues credentials after valid x402 payment
3. Verifies proofs per §11
4. Enforces rate limiting per §10
5. Returns correct error codes per §13
6. Supports at least one registered scheme

---

## Appendix A: Credential Structure (Informative)

```
Credential {
  // Signed by issuer
  service_id: Field
  tier: Field  
  max_presentations: Field
  issued_at: Field
  expires_at: Field
  commitment: (Field, Field)  // Point
  signature: (Point, Scalar)  // Schnorr (R, s)
  
  // Client secrets (never sent)
  nullifier_seed: Field
  blinding_factor: Field
}
```

---

## Appendix B: Example Flow

```
# 1. Initial request
GET /api/data HTTP/1.1
Host: api.example.com

# 2. Server responds with 402 + extension
HTTP/1.1 402 Payment Required
Content-Type: application/json

{
  "x402": {
    "payment_requirements": { 
      "amount": "100000", 
      "asset": "USDC",
      "facilitator": "https://facilitator.example.com/settle"
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

# 3. Client pays via facilitator with commitment
POST https://facilitator.example.com/settle HTTP/1.1
Content-Type: application/json

{
  "payment": { /* x402 payment */ },
  "zk_session": {
    "commitment": "pedersen-schnorr-bn254:0x..."
  }
}

# 4. Facilitator settles payment and returns credential
HTTP/1.1 200 OK
{
  "payment_receipt": { /* x402 receipt */ },
  "zk_session": {
    "credential": {
      "scheme": "pedersen-schnorr-bn254",
      "service_id": "0x...",
      "tier": 1,
      "max_presentations": 1000,
      "issued_at": 1706918400,
      "expires_at": 1707004800,
      "commitment": "0x...",
      "signature": "0x..."
    }
  }
}

# 5. Client generates proof, accesses resource (no payment header needed)
GET /api/data HTTP/1.1
Host: api.example.com
Authorization: ZKSession pedersen-schnorr-bn254:eyJwcm9vZiI6...

# 6. Server verifies proof, returns data
HTTP/1.1 200 OK
{ "data": "..." }

# 7. Subsequent requests reuse credential (different presentation_index)
GET /api/data HTTP/1.1
Host: api.example.com
Authorization: ZKSession pedersen-schnorr-bn254:eyJhbm90aGVy...
```

---

## Appendix C: Rationale

**Facilitator as Issuer:**
- Client already trusts facilitator for payment settlement
- No additional trust assumptions or round trips
- Credential issuance piggybacks on existing payment confirmation
- Separates issuer (facilitator) from verifier (server) naturally

**Payment-first design:**
This extension avoids "proof-only access" pitfalls by:
- Keeping payment as payment (x402 remains about settlement)
- Treating zk-session as post-payment redemption optimization
- Remaining compatible with future session payment schemes (escrow, channels)

**Deterministic origin tokens:**
The deterministic `origin_token` approach (vs. challenge-based nullifiers) was chosen for:
- Single round-trip (no challenge fetch needed)
- Client-controlled privacy/linkability tradeoff
- Simpler server implementation
- Natural fit with per-origin rate limiting
