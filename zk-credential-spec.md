# x402 Extension: ZK Credential

**Extension ID:** `zk-credential`  
**Version:** 0.1.0  
**Status:** Draft  
**Last Updated:** 2026-02-06  
**x402 Compatibility:** v2

---

## 1. Overview

This extension enables **pay-once, redeem-many** access to x402-protected resources using privacy-preserving credentials proved in zero knowledge.

> **Definition:** A `zk_credential` is a payment-bound access credential issued after successful x402 settlement. Clients present ZK proofs of possession to authorize requests without revealing a linkable identifier.

**Design intent:** Keep x402 payment semantics intact. Payment uses standard x402 mechanisms. This extension changes only post-payment redemption, allowing clients to make multiple requests without re-paying and without creating linkable per-user identifiers.

---

## 2. Goals

1. **One payment, multiple requests** — Reduce cost and latency of repeating settlement operations for many API calls.

2. **Unlinkable redemption** — After payment, subsequent requests are unlinkable to the payer identity by the server, beyond unavoidable network metadata.

3. **Minimal protocol disturbance** — Works as an optional extension layered on existing x402 flow. HTTP 402 remains "Payment Required."

4. **Short-lived credentials** — Credentials are time-bounded and usage-bounded.

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
| **Server** | Protected resource server. Verifies ZK proofs for access control. Mediates facilitator communication. |
| **Facilitator** | x402 intermediary that verifies/settles payment AND issues credentials |

The **Facilitator is the Issuer**. This follows naturally from x402's architecture:
- Server already sends payment to facilitator for verification/settlement
- Credential issuance piggybacks on this existing flow
- No additional trust assumptions required

**Note:** In x402 v2, clients communicate only with the server. The server handles all facilitator communication. This extension follows that pattern.

---

## 5. Flow Overview

### 5.1 Standard x402 v2 (reference)

```
1. Client → Server:      GET /resource
2. Server → Client:      402 Payment Required
                         PAYMENT-REQUIRED: <base64 PaymentRequirements>
3. Client → Server:      GET /resource
                         PAYMENT-SIGNATURE: <base64 PaymentPayload>
4. Server → Facilitator: POST /verify (PaymentPayload, PaymentRequirements)
5. Facilitator → Server: VerifyResponse
6. Server → Facilitator: POST /settle (PaymentPayload, PaymentRequirements)
7. Facilitator → Server: SettleResponse
8. Server → Client:      200 OK + resource
                         PAYMENT-RESPONSE: <base64 SettleResponse>
```

### 5.2 x402 v2 + zk-credential

```
PHASE 1: Payment + Credential Issuance (follows x402 v2 canonical flow)
─────────────────────────────────────────────────────────────────────
1. Client → Server:      GET /resource
2. Server → Client:      402 Payment Required
                         PAYMENT-REQUIRED: <base64 PaymentRequirements + zk_credential extension>
3. Client → Server:      POST /resource
                         Content-Type: application/json
                         Body: { payment, zk_credential: { commitment } }
4. Server → Facilitator: POST /settle (payload + zk_credential commitment)
5. Facilitator → Server: SettleResponse + zk_credential credential
6. Server → Client:      200 OK
                         Body: { x402: { payment_response }, zk_credential: { credential } }

PHASE 2: Private Redemption (separate requests, unlinkable to payment)
─────────────────────────────────────────────────────────────────────
7.  Client → Server:     POST /resource
                         Content-Type: application/json
                         Body: { zk_credential: { proof, public_outputs } }
8.  Server:              Verify proof locally (no facilitator call)
9.  Server → Client:     200 OK + resource

(Steps 7-9 repeat until credential expires or identity_limit exhausted)
```

### 5.3 Why Two Phases Are Necessary

**Privacy requires temporal separation.**

In standard x402, the server sees both payment identity (in `PAYMENT-SIGNATURE`) and resource access in the same request. If credential redemption occurred in that same request, the server could trivially link them, defeating the privacy goal.

By separating payment (Phase 1) from redemption (Phase 2):
- Phase 1: Server learns payment identity but only delivers one response
- Phase 2: Server sees only an unlinkable ZK proof with no connection to Phase 1

This is an **intentional deviation** from the "one request after payment" pattern of standard x402, and is fundamental to the privacy guarantee.

---

## 6. Transport

### 6.1 Normative Requirements

1. **Proofs MUST be carried in the HTTP request body**, not headers.
2. **Servers MUST NOT require proofs in headers.**
3. **Credentials MUST be returned in the response body**, not headers.
4. **Large artifacts MUST be in the body**; headers are for routing/signaling only.

### 6.2 Content Types

| Content-Type | Status | Notes |
|--------------|--------|-------|
| `application/json` | REQUIRED | Base64-encoded binary fields |
| `application/cbor` | OPTIONAL | More efficient for binary data |

### 6.3 Request Envelope (Proof Identity)

Clients send the proof, public outputs, and the `current_time` used during proof generation. All other public inputs are server-derived (see §9.2).

The client must transmit `current_time` because the proof is bound to the exact value used during generation. The server uses this value to reconstruct the proof's public inputs, then validates that it falls within ±60s of the server's own clock (see §11.1).

```json
{
  "zk_credential": {
    "version": "0.1.0",
    "suite": "pedersen-schnorr-poseidon-ultrahonk",
    "kid": "key-2026-02",
    "proof": "<base64-encoded-proof>",
    "current_time": 1707004800,
    "public_outputs": {
      "origin_token": "0x...",
      "tier": 1
    }
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `version` | Yes | Spec version for protocol negotiation |
| `suite` | Yes | Suite identifier so server selects correct verifier |
| `kid` | Recommended | Key ID for key rotation (see §18) |
| `proof` | Yes | Base64-encoded ZK proof |
| `current_time` | Yes | Unix timestamp used as public input during proof generation; server validates ±60s drift (§11.1) |
| `public_outputs` | Yes | Circuit outputs |

**`public_outputs` fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `origin_token` | Yes | Unlinkable rate-limiting token (circuit output) |
| `tier` | Yes | Access level (circuit output) |

### 6.4 Response Envelope (Credential Issuance)

```json
{
  "x402": {
    "payment_response": {
      "success": true,
      "transaction": "0x...",
      "network": "eip155:8453"
    }
  },
  "zk_credential": {
    "credential": {
      "suite": "pedersen-schnorr-poseidon-ultrahonk",
      "service_id": "0xabc123...",
      "tier": 1,
      "identity_limit": 1000,
      "expires_at": 1707004800,
      "commitment": "0x...",
      "signature": "0x..."
    }
  }
}
```

### 6.5 Proof Size Expectations

| Proof System | Raw Size | Base64 Size |
|--------------|----------|-------------|
| UltraHonk | ~16 KB | ~22 KB |
| Groth16 | ~200 B | ~270 B |

> **Note:** UltraHonk proofs exceed typical HTTP header limits (8-16 KB). Body transport is required.
> **Recommendation:** Servers SHOULD accept proof bodies up to **64 KB**. Servers MAY set lower limits but MUST return `413 payload_too_large` with the maximum accepted size in the error response.

### 6.6 HTTP Method for Redemption

Since proofs are in the request body, credential redemption uses **POST**:

```
POST /api/resource HTTP/1.1
Content-Type: application/json

{
  "zk_credential": { ... }
}
```

Servers MAY support a token exchange pattern for GET-like semantics:
1. `POST /zk-auth` with proof → receive short-lived bearer token
2. `GET /resource` with `Authorization: Bearer <token>`

---

## 7. Extension Advertisement

When returning `402 Payment Required`, servers supporting zk-credential include the extension in the response body:

```json
{
  "x402Version": 2,
  "accepts": [
    {
      "scheme": "exact",
      "network": "eip155:8453",
      "maxAmountRequired": "100000",
      "resource": "https://api.example.com/data",
      "payTo": "0x1234...",
      "asset": "0xABCD..."
    }
  ],
  "extensions": {
    "zk_credential": {
      "version": "0.1.0",
      "credential_suites": ["pedersen-schnorr-poseidon-ultrahonk"],
      "facilitator_pubkey": "pedersen-schnorr-poseidon-ultrahonk:0x04abc...",
      "max_credential_ttl": 86400
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `version` | Spec version (semver) |
| `credential_suites` | Supported cryptographic suites (see §13) |
| `facilitator_pubkey` | Suite-prefixed issuer public key for credential verification (facilitator acts as issuer) |
| `max_credential_ttl` | Optional. Maximum credential lifetime in seconds |

Clients that don't support zk-credential ignore `extensions.zk_credential` and use standard x402.

---

## 8. Credential Issuance

### 8.1 Client Preparation

Before payment, client generates locally (never sent to anyone):
- `nullifier_seed` — random secret
- `blinding_factor` — random blinding value

Client computes:
- `commitment = Commit(nullifier_seed, blinding_factor)` — hiding commitment

### 8.2 Payment Request with Commitment

Client sends payment with commitment in request body:

```json
{
  "x402Version": 2,
  "payment": {
    "scheme": "exact",
    "network": "eip155:8453",
    "payload": {
      "signature": "0x...",
      "authorization": { ... }
    }
  },
  "extensions": {
    "zk_credential": {
      "commitment": "pedersen-schnorr-poseidon-ultrahonk:0x..."
    }
  }
}
```

### 8.3 Server Forwards to Facilitator

Server calls facilitator's `/settle` endpoint:

```json
{
  "paymentPayload": { /* from request */ },
  "paymentRequirements": { /* from server config */ },
  "extensions": {
    "zk_credential": {
      "commitment": "pedersen-schnorr-poseidon-ultrahonk:0x..."
    }
  }
}
```

### 8.4 Facilitator Response with Credential

Facilitator returns credential in settlement response body:

```json
{
  "success": true,
  "transaction": "0x...",
  "network": "eip155:8453",
  "payer": "0x...",
  "extensions": {
    "zk_credential": {
      "credential": {
        "suite": "pedersen-schnorr-poseidon-ultrahonk",
        "service_id": "0xabc123...",
        "tier": 1,
        "identity_limit": 1000,
        "expires_at": 1707004800,
        "commitment": "0x...",
        "signature": "0x..."
      }
    }
  }
}
```

### 8.5 Server Returns Credential to Client

Server returns credential in response body (not header):

```json
{
  "x402": {
    "payment_response": {
      "success": true,
      "transaction": "0x...",
      "network": "eip155:8453"
    }
  },
  "zk_credential": {
    "credential": { ... }
  },
  "data": { /* first response payload (OPTIONAL) */ }
}
```

> **Note:** Servers MAY include the requested resource in the Phase 1 response alongside the credential. Clients seeking maximum privacy MAY discard the Phase 1 response data and re-request via Phase 2 using an unlinkable proof.

### 8.6 Credential Fields

| Field | Description |
|-------|-------------|
| `suite` | Cryptographic suite used |
| `service_id` | Identifies the service/API |
| `tier` | Access level (0, 1, 2, ...) — derived from payment amount |
| `identity_limit` | Maximum distinct identities derivable from credential |
| `expires_at` | Unix timestamp of expiration |
| `commitment` | Client's commitment (echoed back) |
| `signature` | Facilitator signature over all fields |

**Facilitator MUST NOT** store or log commitment-to-payment mappings beyond immediate operational needs.

---

## 9. Credential Identity (Private Redemption)

### 9.1 Transport

Clients present credentials via POST request body:

```
POST /api/resource HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "zk_credential": {
    "version": "0.1.0",
    "suite": "pedersen-schnorr-poseidon-ultrahonk",
    "kid": "key-2026-02",
    "proof": "<base64-proof>",
    "current_time": 1707004800,
    "public_outputs": {
      "origin_token": "0x...",
      "tier": 1
    }
  }
}
```

The `kid` field identifies which issuer key was used to sign the credential. The server uses this to select the corresponding public key for proof verification (see §18).

### 9.2 Proof Public Inputs

The server constructs public inputs from its own configuration and the client-provided `current_time`:

| Input | Source |
|-------|--------|
| `service_id` | Server configuration (see §10.4) |
| `current_time` | From client's `zk_credential.current_time`; validated within ±60s of server clock (§11.1) |
| `origin_id` | Computed from request URL per §10 |
| `facilitator_pubkey` | Looked up by `kid` from request (see §18) |

> **Why `current_time` is client-provided:** The proof is cryptographically bound to the exact `current_time` used during generation. If the server substituted its own clock value, verification would fail whenever the two clocks differ. Instead, the client transmits the value it used, and the server validates it is within acceptable drift before using it for verification.

### 9.3 Proof Public Outputs

The proof produces:

| Output | Purpose |
|--------|---------|
| `origin_token` | Unlinkable rate-limiting token |
| `tier` | Access level for authorization |

---

## 10. Origin ID Computation

### 10.1 Definition

`origin_id` binds proofs to specific endpoints, preventing cross-endpoint replay.

**Normative computation:**

```
origin_id = Poseidon(stringToField(canonical_origin))
```

Where `canonical_origin` is:
```
scheme + "://" + lowercase(host) + normalized_path
```

### 10.2 Normalization Rules

| Component | Rule |
|-----------|------|
| Scheme | Lowercase (`https`) |
| Host | Lowercase, include port only if non-default |
| Path | Preserve case, strip trailing slash |
| Query | MUST NOT include |

**Examples:**
- `https://api.example.com/v1/data` → valid
- `https://api.example.com/v1/data/` → normalized to above
- `https://API.Example.COM/v1/data` → normalized to above

### 10.3 Security Binding

Credentials/proofs MUST bind to:
- **Audience** — via `service_id` + `origin_id`
- **Scope** — via `origin_id`
- **Expiry** — via `expires_at`
- **Tier** — if applicable

> **Security Note:** Without host in `origin_id`, proofs can be replayed across servers sharing an issuer key.

### 10.4 Service ID

`service_id` identifies the service/API and binds credentials to a specific deployment.

**Assignment options:**
1. **Facilitator-assigned:** Opaque identifier assigned during service registration. Facilitators MUST ensure uniqueness.
2. **Derived:** `service_id = Poseidon(stringToField(scheme + "://" + host))` where host is the canonical service origin.

Servers MUST use a consistent `service_id` across all endpoints. Different `origin_id` values provide per-endpoint granularity within a single `service_id`.

---

## 11. Proof Statement

The ZK proof MUST prove:

1. **Commitment opening** — Prover knows `(nullifier_seed, blinding_factor)` that open the credential's commitment

2. **Valid signature** — Issuer's signature over the credential's service binding, tier, identity limit, expiry, and commitment is valid

3. **Service binding** — Credential's `service_id` matches public input

4. **Not expired** — `expires_at >= current_time`

5. **Identity bound** — `identity_index < identity_limit`

6. **Origin token derivation** — `origin_token = hash(nullifier_seed, origin_id, identity_index)`

**Public outputs:** `(origin_token, tier)`

### 11.1 Clock Skew Tolerance

The circuit uses `current_time` as a public input. The client chooses this value at proof generation time and transmits it in `zk_credential.current_time` (§6.3). The server uses the client-provided value to reconstruct public inputs for proof verification, but MUST validate it against the server's own clock:

- Servers MUST reject requests where `|zk_credential.current_time - server_clock| > 60 seconds`.
- This drift check MUST occur **before** proof verification to avoid wasting computation on stale proofs.
- Servers MAY include their current time in the 402 response for client synchronization:
  ```json
  { "server_time": 1707004800, ... }
  ```
- Clients generating proofs SHOULD use a recent server-provided timestamp when available, falling back to their own clock.

---

## 12. Rate Limiting and Replay Prevention

### 12.1 Origin Token

```
origin_token = hash(nullifier_seed, origin_id, identity_index)
```

Properties:
- **Deterministic** — Same inputs produce same token
- **Origin-bound** — Different endpoints produce different tokens
- **Unlinkable across origins** — Tokens for `/api/foo` and `/api/bar` are unlinkable
- **Client-controlled linkability** — Reusing `identity_index` produces same token (linkable); incrementing produces different token (unlinkable)

### 12.2 Server Modes

**Strict one-time identity mode:**
- Server caches seen `origin_token` values until credential expiry
- Duplicate tokens are rejected
- Maximum privacy, higher storage cost

**Reusable identity mode:**
- Server accepts repeated `origin_token` values
- Rate limiting applied per token
- Lower privacy, lower storage cost

### 12.3 Server Behavior

Servers track `origin_token` usage:
- Cache is non-identity, TTL-bounded (by credential `expires_at`)
- New token → allow, start tracking
- Known token within window → increment count, check limit (reusable mode)
- Known token → reject (strict mode)
- Token exceeds limit → reject (429)

### 12.4 Client Behavior

Clients manage `identity_index`:
- **Maximum privacy:** Increment for every request (different token each time)
- **Stable identity per origin:** Reuse same index per origin
- **Hybrid:** Increment within session, reset across sessions

### 12.5 Client-Side Proof Caching

Clients MAY cache proofs for reuse within the same identity index.

Cached proofs become invalid when:
- `current_time` drift exceeds server tolerance (recommended: 60s)
- Origin changes
- Credential is refreshed/replaced
- Credential is expired (`expires_at` has passed)

---

## 13. Credential Suite Registry

A credential suite defines the complete cryptographic stack. Suite identifiers are opaque labels mapping to specifications.

| Suite ID | Commitment | Signature | Hash | Proof System | Curve |
|----------|------------|-----------|------|--------------|-------|
| `pedersen-schnorr-poseidon-ultrahonk` | Pedersen | Schnorr | Poseidon | UltraHonk | BN254 |
| `pedersen-schnorr-poseidon-groth16` | Pedersen | Schnorr | Poseidon | Groth16 | BN254 |

### 13.1 Suite: `pedersen-schnorr-poseidon-ultrahonk`

Reference implementation: `x402-zk-credential-noir`

| Component | Specification |
|-----------|---------------|
| Curve | BN254 (alt_bn128) |
| Commitment | Pedersen with standard generators |
| Signature | Schnorr (R, s) |
| Hash | Poseidon (t=3, RF=8, RP=57) |
| Proof system | UltraHonk |

### 13.2 Wire Encoding

All binary fields are hex-encoded with `0x` prefix when transmitted as JSON strings.

| Type | Encoding | Size |
|------|----------|------|
| **Field element** | 32-byte big-endian | 64 hex chars |
| **Scalar** | 32-byte big-endian | 64 hex chars |
| **Point (uncompressed)** | `04` \|\| x (32 bytes) \|\| y (32 bytes) | 130 hex chars |
| **Point (compressed)** | `02`/`03` \|\| x (32 bytes) | 66 hex chars |

**Commitment encoding:**

Commitments are curve points. Wire format uses suite prefix + uncompressed point:
```
"commitment": "pedersen-schnorr-poseidon-ultrahonk:0x04<x><y>"
```

Where `<x>` and `<y>` are 32-byte hex-encoded coordinates.

**Signature encoding:**

Schnorr signatures consist of `(R, s)` where R is a point and s is a scalar. Wire format concatenates components:
```
"signature": "0x<R_x><R_y><s>"
```

Where:
- `R_x`: 32 bytes (x-coordinate of R)
- `R_y`: 32 bytes (y-coordinate of R)
- `s`: 32 bytes (scalar)

Total: 96 bytes = 192 hex characters.

**Proof encoding:**

Proofs are opaque binary blobs, base64-encoded:
```
"proof": "<base64-encoded-bytes>"
```

---

## 14. Error Responses

### 14.1 Error Codes

| Code | HTTP | Meaning |
|------|------|---------|
| `credential_missing` | 402 | No credential provided |
| `tier_insufficient` | 402 | Tier below requirement |
| `unsupported_suite` | 400 | Suite not supported |
| `invalid_proof` | 400 | Proof verification failed (includes expired credentials, see note below) |
| `payload_too_large` | 413 | Proof body exceeds size limit |
| `origin_mismatch` | 400 | Proof origin binding does not match request URL (if detected) |
| `unsupported_media_type` | 415 | Content-Type not supported |
| `rate_limited` | 429 | Origin token rate limited |

> **Note:** Because `expires_at` is a private input enforced inside the circuit, the server cannot distinguish an expired credential from other proof failures. Both result in `invalid_proof`. Clients SHOULD track credential expiry locally and re-enter the payment flow before attempting to prove with an expired credential.

### 14.2 Structured Error Envelope

All error responses use this JSON structure:

```json
{
  "error": "invalid_proof",
  "code": 400,
  "message": "Proof verification failed",
  "retry_after": 0,
  "credential_endpoint": "https://issuer.example.com/credentials/issue",
  "payment_requirements": { ... }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `error` | Yes | Machine-readable error code |
| `code` | Yes | HTTP status code |
| `message` | No | Human-readable description |
| `retry_after` | No | Seconds until retry (for rate limits) |
| `max_body_bytes` | No | Maximum accepted proof body size (for 413) |
| `credential_endpoint` | No | URL to obtain new credential |
| `payment_requirements` | No | x402 payment requirements (for 402) |

### 14.3 Expired Credentials

Credential expiry (`expires_at >= current_time`) is enforced inside the circuit as a private constraint. The server never sees `expires_at` — an expired credential simply produces an invalid proof, returned as `invalid_proof`.

**Client responsibility:** Clients MUST track `expires_at` locally and initiate a new payment flow before the credential expires. When a client detects local expiry:

1. Discard the expired credential
2. Re-discover the API (GET the protected endpoint to receive 402 with payment requirements)
3. Complete a new payment to obtain a fresh credential

**Server behavior:** If a proof fails verification for any reason (expired, wrong service, bad signature, etc.), the server returns:

```
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid_proof",
  "code": 400,
  "message": "Proof verification failed"
}
```

The server MAY include `payment_requirements` in the error response to help clients re-enter the payment flow.

---

## 15. Verification Flow

Server steps for requests with `zk_credential` in body:

1. Parse request body for `zk_credential` object
2. Extract `suite`, `kid`, and `proof`
3. If unsupported suite → `400 unsupported_suite`
4. If body too large → `413 payload_too_large` (include `max_body_bytes`)
5. Look up `facilitator_pubkey` using `kid` (see §18). If unknown → `400 invalid_proof`
6. Compute `origin_id` from request URL per §10
7. Extract `current_time` from client's `zk_credential.current_time`
8. If `|current_time - server_clock| > 60s` → `400 invalid_proof` (clock drift exceeded)
9. Construct public inputs: `(service_id, current_time, origin_id, facilitator_pubkey)`
10. Verify proof locally (no facilitator call needed)
11. If invalid → `400 invalid_proof`
12. Extract outputs: `(origin_token, tier)`
13. Check rate limit for `origin_token`
14. If exceeded → `429 rate_limited`
15. Check `tier` meets endpoint requirement
16. If insufficient → `402 tier_insufficient`
17. Allow request

Server steps for requests without `zk_credential`:

1. Check for payment in body
2. If present → process as standard x402 payment (with credential issuance)
3. If absent → return `402` with payment requirements and `zk_credential` extension

---

## 16. Security Properties

### 16.1 Required Properties

| Property | Requirement |
|----------|-------------|
| **Issuer blindness** | Issuer MUST NOT learn `nullifier_seed` from commitment |
| **Unforgeability** | Credentials MUST NOT be forgeable without issuer key |
| **Credential hiding** | Proof MUST NOT reveal which credential is used |
| **Origin unlinkability** | Different `origin_id` MUST produce unlinkable tokens |
| **Public verifiability** | Proof MUST be verifiable without issuer interaction |

### 16.2 What This Provides

- Server verifies "paid + authorized" without learning stable client identifier
- Repeated requests don't require repeated payment artifacts
- Different API endpoints see unlinkable tokens
- Payment identity (Phase 1) is unlinkable to redemption (Phase 2)

### 16.3 What This Does Not Prevent

- Correlation via IP, TLS fingerprint, timing, cookies
- Timing correlation at issuance (credential issued immediately after payment)
- Credential theft (mitigate with short expiry)

---

## 17. Security Considerations

| Threat | Mitigation |
|--------|------------|
| Issuer key compromise | Key rotation, short credential expiry |
| Credential theft | Short expiry, `identity_limit` limit |
| Replay attacks | `identity_index` in token derivation |
| Time manipulation | Client provides `current_time`; server rejects if drift from its own clock exceeds ±60s; circuit enforces `expires_at >= current_time` privately (server cannot distinguish expiry from other failures) |
| DoS via verification | Rate limiting, proof size limits |
| Cross-server replay | `origin_id` includes host |

### 17.1 Timing Correlation Attack

**Attack:** Issuers can link wallet addresses to commitments via timing — credentials are issued immediately after payment.

**Mitigations (non-normative):**
- Clients SHOULD delay credential requests or batch with other users
- Consider decoupled payment token approach:
  1. Pay → receive opaque token
  2. Redeem token for credential (breaks timing link)

---

## 18. Key Rotation

### 18.1 Rotation Lifecycle

1. New key published with `valid_from` timestamp
2. Old key remains valid for overlapping window (max credential duration)
3. Credentials signed with old key remain valid until their own `expires_at`

### 18.2 Key Discovery

Servers SHOULD expose issuer keys at:
```
GET /.well-known/zk-credential-keys
```

Response:
```json
{
  "keys": [
    {
      "kid": "key-2026-02",
      "suite": "pedersen-schnorr-poseidon-ultrahonk",
      "pubkey": "0x04...",
      "valid_from": 1706918400,
      "valid_until": null
    },
    {
      "kid": "key-2026-01",
      "suite": "pedersen-schnorr-poseidon-ultrahonk",
      "pubkey": "0x04...",
      "valid_from": 1704240000,
      "valid_until": 1707004800
    }
  ]
}
```

---

## 19. Privacy Considerations

| Property | Status | Notes |
|----------|--------|-------|
| Payment-redemption unlinkability | ✓ | Separate requests, ZK proof hides credential |
| Cross-origin unlinkability | ✓ | Different `origin_id` → different token |
| Within-origin linkability | Configurable | Client controls via `identity_index` |
| Payment-credential timing | Partial | Credential issued with payment response |

**Timing correlation mitigation (RECOMMENDED):**
- Delay first redemption request after receiving credential
- Use different network path for redemption vs payment
- Batch credential requests if possible

---

## 20. Compatibility

### 20.1 x402 v2 Compatibility

- Uses x402 v2 conventions for payment flow
- Extension data in `extensions.zk_credential`
- Uses CAIP-2 network identifiers (e.g., `eip155:8453` for Base)
- Server↔Facilitator communication follows canonical v2 flow
- Requires facilitator support for zk-credential extension

### 20.2 Facilitator Requirements

This extension requires a facilitator that:
- Accepts `extensions.zk_credential.commitment` in settle requests
- Returns `extensions.zk_credential.credential` in settle responses
- Does not log commitment-to-payment mappings

### 20.3 Backwards Compatibility

- Non-implementing clients ignore `extensions.zk_credential` and use standard x402
- Non-implementing servers return standard x402 responses
- Multiple suites can coexist; client picks from server's list

### 20.4 Naming Convention

- Extension ID (string identifier): `zk-credential`
- JSON object key: `zk_credential`

---

## 21. Conformance

An implementation conforms to this specification if it:

1. Advertises support via `extensions.zk_credential` in 402 response body
2. Accepts proofs in request body (not headers)
3. Returns credentials in response body (not headers)
4. Forwards commitment to facilitator during settlement
5. Verifies ZK proofs per §15
6. Enforces rate limiting per §12
7. Returns correct error codes per §14
8. Supports at least one registered suite
9. Computes `origin_id` per §10

---

## Appendix A: Credential Structure (Informative)

```
Credential {
  // Signed by issuer (facilitator)
  service_id: Field
  tier: Field  
  identity_limit: Field
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
# ═══════════════════════════════════════════════════════════════════
# PHASE 1: Payment + Credential Issuance
# ═══════════════════════════════════════════════════════════════════

# 1. Client requests resource
GET /api/data HTTP/1.1
Host: api.example.com

# 2. Server returns 402 with zk-credential extension
HTTP/1.1 402 Payment Required
Content-Type: application/json

{
  "x402Version": 2,
  "accepts": [{
    "scheme": "exact",
    "network": "eip155:8453",
    "amount": "100000",
    "payTo": "0x1234..."
  }],
  "extensions": {
    "zk_credential": {
      "version": "0.1.0",
      "credential_suites": ["pedersen-schnorr-poseidon-ultrahonk"],
      "facilitator_pubkey": "pedersen-schnorr-poseidon-ultrahonk:0x04..."
    }
  }
}

# 3. Client sends payment with commitment (POST, body)
POST /api/data HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "x402Version": 2,
  "payment": {
    "scheme": "exact",
    "network": "eip155:8453",
    "payload": {"signature": "0x...", "authorization": {...}}
  },
  "extensions": {
    "zk_credential": {
      "commitment": "pedersen-schnorr-poseidon-ultrahonk:0x..."
    }
  }
}

# 4-5. Server → Facilitator: /settle (with commitment)
#      Facilitator returns settlement + credential

# 6. Server returns resource + credential (in body)
HTTP/1.1 200 OK
Content-Type: application/json

{
  "x402": {
    "payment_response": {
      "success": true,
      "transaction": "0x8f3d...",
      "network": "eip155:8453"
    }
  },
  "zk_credential": {
    "credential": {
      "suite": "pedersen-schnorr-poseidon-ultrahonk",
      "kid": "key-2026-02",
      "service_id": "0xabc123...",
      "tier": 1,
      "identity_limit": 1000,
      "expires_at": 1707004800,
      "commitment": "0x04<x><y>",
      "signature": "0x<R_x><R_y><s>"
    }
  },
  "data": "first response (optional)"
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 2: Private Redemption (unlinkable to Phase 1)
# ═══════════════════════════════════════════════════════════════════

# 7. Client generates ZK proof and requests resource (POST, body)
POST /api/data HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "zk_credential": {
    "version": "0.1.0",
    "suite": "pedersen-schnorr-poseidon-ultrahonk",
    "kid": "key-2026-02",
    "proof": "<base64-encoded-proof>",
    "public_outputs": {
      "origin_token": "0x...",
      "tier": 1
    }
  }
}

# 8. Server verifies proof locally (no facilitator call)

# 9. Server returns resource
HTTP/1.1 200 OK
Content-Type: application/json

{"data": "response via private redemption"}
```

---

## Appendix C: Rationale

**Body transport instead of headers:**
UltraHonk proofs are ~16KB raw, ~22KB base64. This exceeds HTTP header limits (8-16KB) in most gateways. Body transport is required for practical deployment.

**POST for redemption:**
Since proofs are in the body, GET is not appropriate. POST with proof enables stateless verification.

**Two-phase flow for privacy:**
If credential redemption occurred in the same request as payment, the server would trivially link payment identity to access. Separating payment (Phase 1) from redemption (Phase 2) is what enables unlinkability.

**Facilitator as Issuer:**
- Server already trusts facilitator for payment settlement
- No additional trust assumptions
- Credential issuance piggybacks on existing settlement response

**`expires_at` checked inside circuit:**
The circuit checks `expires_at >= current_time` internally. This keeps `expires_at` private (not leaked as a public output) while still enforcing freshness via the server-provided `current_time` public input.

**`identity_limit` naming:**
Clarifies semantic: maximum distinct identities derivable, not "uses". Circuit enforces `identity_index < identity_limit`.

