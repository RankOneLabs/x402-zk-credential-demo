# x402 Extension: ZK Session Credentials

**Extension ID:** `zk-session`  
**Version:** 0.1.0  
**Status:** Draft  
**Last Updated:** 2026-02-04  
**x402 Compatibility:** v2

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
| **Server** | Protected resource server. Verifies ZK proofs for access control. Mediates facilitator communication. |
| **Facilitator** | x402 intermediary that verifies/settles payment AND issues session credentials |

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

### 5.2 x402 v2 + zk-session

```
PHASE 1: Payment + Credential Issuance (follows x402 v2 canonical flow)
─────────────────────────────────────────────────────────────────────
1. Client → Server:      GET /resource
2. Server → Client:      402 Payment Required
                         PAYMENT-REQUIRED: <base64 PaymentRequirements + zk_session extension>
3. Client → Server:      GET /resource
                         PAYMENT-SIGNATURE: <base64 PaymentPayload + zk_session commitment>
4. Server → Facilitator: POST /verify (PaymentPayload, PaymentRequirements)
5. Facilitator → Server: VerifyResponse
6. Server → Facilitator: POST /settle (PaymentPayload, PaymentRequirements, zk_session commitment)
7. Facilitator → Server: SettleResponse + zk_session credential
8. Server → Client:      200 OK + resource
                         PAYMENT-RESPONSE: <base64 SettleResponse + zk_session credential>

PHASE 2: Private Redemption (separate requests, unlinkable to payment)
─────────────────────────────────────────────────────────────────────
9.  Client → Server:     GET /resource
                         Authorization: ZKSession <scheme>:<base64-proof>
10. Server:              Verify proof locally (no facilitator call)
11. Server → Client:     200 OK + resource

(Steps 9-11 repeat until credential expires or max_presentations reached)
```

### 5.3 Why Two Phases Are Necessary

**Privacy requires temporal separation.**

In standard x402, the server sees both payment identity (in `PAYMENT-SIGNATURE`) and resource access in the same request. If zk-session redemption occurred in that same request, the server could trivially link them, defeating the privacy goal.

By separating payment (Phase 1) from redemption (Phase 2):
- Phase 1: Server learns payment identity but only delivers one response
- Phase 2: Server sees only an unlinkable ZK proof with no connection to Phase 1

This is an **intentional deviation** from the "one request after payment" pattern of standard x402, and is fundamental to the privacy guarantee.

---

## 6. Extension Advertisement

When returning `402 Payment Required`, servers supporting zk-session include the extension in the `PAYMENT-REQUIRED` header payload:

```
HTTP/1.1 402 Payment Required
PAYMENT-REQUIRED: <base64-encoded payload below>
```

**Decoded payload:**

```json
{
  "x402Version": 2,
  "accepts": [
    {
      "scheme": "exact",
      "network": "eip155:8453",
      "maxAmountRequired": "100000",
      "resource": "https://api.example.com/data",
      "description": "API access",
      "payTo": "0x1234...",
      "maxTimeoutSeconds": 300,
      "asset": "0xABCD...",
      "extra": null
    }
  ],
  "extensions": {
    "zk_session": {
      "version": "0.1",
      "schemes": ["pedersen-schnorr-bn254"],
      "facilitator_pubkey": "pedersen-schnorr-bn254:0x04abc...",
      "max_credential_ttl": 86400
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `version` | Spec version |
| `schemes` | Supported cryptographic schemes (see §12) |
| `facilitator_pubkey` | Scheme-prefixed public key for credential verification |
| `max_credential_ttl` | Optional. Maximum credential lifetime in seconds the server will accept |

Clients that don't support zk-session ignore `extensions.zk_session` and use standard x402.

---

## 7. Credential Issuance

### 7.1 Client Preparation

Before payment, client generates locally (never sent to anyone):
- `nullifier_seed` — random secret
- `blinding_factor` — random blinding value

Client computes:
- `commitment = Commit(nullifier_seed, blinding_factor)` — hiding commitment

### 7.2 Payment Request with Commitment

Client includes commitment in the `extensions` object of the `PAYMENT-SIGNATURE` payload:

```json
{
  "x402Version": 2,
  "scheme": "exact",
  "network": "eip155:8453",
  "payload": {
    "signature": "0x...",
    "authorization": {
      "from": "0x...",
      "to": "0x...",
      "value": "100000",
      "validAfter": "1706918400",
      "validBefore": "1706922000",
      "nonce": "0x..."
    }
  },
  "extensions": {
    "zk_session": {
      "commitment": "pedersen-schnorr-bn254:0x..."
    }
  }
}
```

### 7.3 Server Forwards to Facilitator

Server calls facilitator's `/settle` endpoint with standard v2 fields plus zk-session extension:

**Request to facilitator:**

```json
{
  "paymentPayload": { /* from PAYMENT-SIGNATURE */ },
  "paymentRequirements": { /* from server config */ },
  "extensions": {
    "zk_session": {
      "commitment": "pedersen-schnorr-bn254:0x..."
    }
  }
}
```

**Note:** This requires a facilitator that supports the zk-session extension. Non-supporting facilitators will ignore the `extensions` field and process standard settlement only.

### 7.4 Facilitator Response with Credential

Facilitator returns credential in the settlement response:

```json
{
  "success": true,
  "transaction": "0x...",
  "network": "eip155:8453",
  "payer": "0x...",
  "extensions": {
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
}
```

### 7.5 Server Returns Credential to Client

Server includes the credential in the `PAYMENT-RESPONSE` header:

```
HTTP/1.1 200 OK
PAYMENT-RESPONSE: <base64-encoded payload below>
Content-Type: application/json

{"data": "...first response..."}
```

**Decoded PAYMENT-RESPONSE:**

```json
{
  "success": true,
  "transaction": "0x...",
  "network": "eip155:8453",
  "extensions": {
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
}
```

### 7.6 Credential Fields

| Field | Description |
|-------|-------------|
| `scheme` | Cryptographic scheme used |
| `service_id` | Identifies the service/API (RECOMMENDED: hash of resource URL or server-assigned) |
| `tier` | Access level (0, 1, 2, ...) — derived from payment amount |
| `max_presentations` | Maximum proof presentations allowed |
| `issued_at` | Unix timestamp of issuance |
| `expires_at` | Unix timestamp of expiration |
| `commitment` | Client's commitment (echoed back) |
| `signature` | Facilitator signature over all fields |

**Facilitator MUST NOT** store or log commitment-to-payment mappings beyond immediate operational needs.

---

## 8. Credential Presentation (Private Redemption)

### 8.1 Transport

For subsequent requests, clients present credentials via the `Authorization` header:

```
Authorization: ZKSession <scheme>:<base64-proof>
```

Example:
```
GET /api/resource HTTP/1.1
Host: api.example.com
Authorization: ZKSession pedersen-schnorr-bn254:eyJwcm9vZiI6...
```

**Note:** The `Authorization` header is used instead of `PAYMENT-SIGNATURE` because:
- ZK proofs are redemption tokens, not payment payloads
- This allows servers to distinguish payment requests from redemption requests
- Redemption does not require facilitator involvement

### 8.2 Proof Public Inputs

The server provides or derives these values for verification:

| Input | Source |
|-------|--------|
| `service_id` | Server configuration |
| `current_time` | Server clock (unix timestamp) |
| `origin_id` | `hash(method + path)` or server-assigned |
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

Server steps for requests with `Authorization: ZKSession` header:

1. Parse `Authorization` header for `ZKSession` prefix
2. Extract scheme and base64-encoded proof
3. If unsupported scheme → `400 unsupported_zk_scheme`
4. Construct public inputs: `(service_id, current_time, origin_id, facilitator_pubkey)`
5. Verify proof locally (no facilitator call needed)
6. If invalid → `401 invalid_zk_proof`
7. Extract outputs: `(origin_token, tier)`
8. Check rate limit for `origin_token`
9. If exceeded → `429 rate_limited`
10. Check `tier` meets endpoint requirement
11. If insufficient → `403 tier_insufficient`
12. Allow request

Server steps for requests without `Authorization: ZKSession`:

1. Check for `PAYMENT-SIGNATURE` header
2. If present → process as standard x402 payment (with zk-session credential issuance if extension present)
3. If absent → return `402` with `PAYMENT-REQUIRED` header (including `extensions.zk_session`)

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
| `tier_insufficient` | 403 | Tier below requirement |
| `rate_limited` | 429 | Origin token rate limited |

### 13.1 Missing or Expired Credentials

When a request has no valid `Authorization: ZKSession` header and no `PAYMENT-SIGNATURE` header, return 402 to trigger re-negotiation:

```
HTTP/1.1 402 Payment Required
PAYMENT-REQUIRED: <base64 payload with extensions.zk_session>
```

This allows clients to obtain a new credential through the standard payment flow.

### 13.2 Invalid ZK Proof

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "invalid_zk_proof",
  "message": "ZK proof verification failed"
}
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
- Payment identity (Phase 1) is unlinkable to redemption (Phase 2)

### 14.3 What This Does Not Prevent

- Correlation via IP, TLS fingerprint, timing, cookies
- Timing correlation at issuance (credential issued immediately after payment)
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
| Payment-redemption unlinkability | ✓ | Separate requests, ZK proof hides credential |
| Cross-origin unlinkability | ✓ | Different `origin_id` → different token |
| Within-origin linkability | Configurable | Client controls via `presentation_index` |
| Payment-credential timing | Partial | Credential issued with payment response |

**Timing correlation mitigation (RECOMMENDED):**
- Delay first redemption request after receiving credential
- Use different network path for redemption vs payment
- Batch credential requests if possible

---

## 17. Compatibility

### 17.1 x402 v2 Compatibility

- Uses x402 v2 header conventions (`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`)
- Extension data in `extensions.zk_session` within standard payloads
- Uses CAIP-2 network identifiers (e.g., `eip155:8453` for Base)
- Server↔Facilitator communication follows canonical v2 flow
- Requires facilitator support for zk-session extension

### 17.2 Facilitator Requirements

This extension requires a facilitator that:
- Accepts `extensions.zk_session.commitment` in settle requests
- Returns `extensions.zk_session.credential` in settle responses
- Does not log commitment-to-payment mappings

Standard facilitators that don't support zk-session will process payment normally but not issue credentials.

### 17.3 Backwards Compatibility

- Non-implementing clients ignore `extensions.zk_session` and use standard x402
- Non-implementing servers ignore `Authorization: ZKSession` and require payment per request
- Multiple schemes can coexist; client picks from server's `schemes` list

### 17.4 Naming Convention

- Extension ID (string identifier): `zk-session`
- JSON object key: `zk_session`

**x402 semantics note (normative):**
- A server MUST return `402 Payment Required` when neither a valid `PAYMENT-SIGNATURE` header nor a valid `Authorization: ZKSession` header is present.
- zk-session changes the *post-payment redemption path* only; it does not redefine what a `402` means.

---

## 18. Conformance

An implementation conforms to this specification if it:

1. Advertises support via `extensions.zk_session` in 402 `PAYMENT-REQUIRED` payload
2. Forwards commitment to facilitator during settlement
3. Returns credential to client in `PAYMENT-RESPONSE`
4. Verifies ZK proofs per §11
5. Enforces rate limiting per §10
6. Returns correct error codes per §13
7. Supports at least one registered scheme
8. Uses x402 v2 conventions for server↔facilitator communication

---

## Appendix A: Credential Structure (Informative)

```
Credential {
  // Signed by issuer (facilitator)
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
# ═══════════════════════════════════════════════════════════════════
# PHASE 1: Payment + Credential Issuance
# ═══════════════════════════════════════════════════════════════════

# 1. Client requests resource
GET /api/data HTTP/1.1
Host: api.example.com

# 2. Server returns 402 with zk-session extension
HTTP/1.1 402 Payment Required
PAYMENT-REQUIRED: eyJ4NDAyVmVyc2lvbiI6MiwiYWNjZXB0cyI6W3t9XSwiZXh0ZW5zaW9ucyI6eyJ6a19zZXNzaW9uIjp7InZlcnNpb24iOiIwLjEiLCJzY2hlbWVzIjpbInBlZGVyc2VuLXNjaG5vcnItYm4yNTQiXX19fQ==

# Decoded:
# {
#   "x402Version": 2,
#   "accepts": [{"scheme": "exact", "network": "eip155:8453", ...}],
#   "extensions": {
#     "zk_session": {
#       "version": "0.1",
#       "schemes": ["pedersen-schnorr-bn254"],
#       "facilitator_pubkey": "pedersen-schnorr-bn254:0x04..."
#     }
#   }
# }

# 3. Client sends payment with commitment
GET /api/data HTTP/1.1
Host: api.example.com
PAYMENT-SIGNATURE: eyJ4NDAyVmVyc2lvbiI6Miwic2NoZW1lIjoiZXhhY3QiLCJwYXlsb2FkIjp7fSwiZXh0ZW5zaW9ucyI6eyJ6a19zZXNzaW9uIjp7ImNvbW1pdG1lbnQiOiIweDEyMzQifX19

# Decoded:
# {
#   "x402Version": 2,
#   "scheme": "exact",
#   "network": "eip155:8453",
#   "payload": {"signature": "0x...", "authorization": {...}},
#   "extensions": {
#     "zk_session": {
#       "commitment": "pedersen-schnorr-bn254:0x..."
#     }
#   }
# }

# 4-7. Server → Facilitator: /verify then /settle (with commitment)
#      Facilitator returns settlement + credential

# 8. Server returns resource + credential
HTTP/1.1 200 OK
PAYMENT-RESPONSE: eyJzdWNjZXNzIjp0cnVlLCJ0cmFuc2FjdGlvbiI6IjB4Li4uIiwiZXh0ZW5zaW9ucyI6eyJ6a19zZXNzaW9uIjp7ImNyZWRlbnRpYWwiOnt9fX19
Content-Type: application/json

{"data": "first response with payment"}

# Decoded PAYMENT-RESPONSE:
# {
#   "success": true,
#   "transaction": "0x8f3d...",
#   "network": "eip155:8453",
#   "extensions": {
#     "zk_session": {
#       "credential": {
#         "scheme": "pedersen-schnorr-bn254",
#         "service_id": "0xabc123...",
#         "tier": 1,
#         "max_presentations": 1000,
#         "issued_at": 1706918400,
#         "expires_at": 1707004800,
#         "commitment": "0x...",
#         "signature": "0x..."
#       }
#     }
#   }
# }

# ═══════════════════════════════════════════════════════════════════
# PHASE 2: Private Redemption (unlinkable to Phase 1)
# ═══════════════════════════════════════════════════════════════════

# 9. Client generates ZK proof and requests resource
GET /api/data HTTP/1.1
Host: api.example.com
Authorization: ZKSession pedersen-schnorr-bn254:eyJwcm9vZiI6Li4ufQ==

# 10. Server verifies proof locally (no facilitator call)

# 11. Server returns resource
HTTP/1.1 200 OK
Content-Type: application/json

{"data": "response via private redemption"}

# 12. Subsequent requests use new presentation_index (unlinkable)
GET /api/data HTTP/1.1
Host: api.example.com
Authorization: ZKSession pedersen-schnorr-bn254:eyJwcm9vZiI6bmV3Li4ufQ==
```

---

## Appendix C: Rationale

**Two-phase flow for privacy:**
If credential redemption occurred in the same request as payment, the server would trivially link payment identity to access. Separating payment (Phase 1) from redemption (Phase 2) is what enables unlinkability. This is an intentional deviation from standard x402's single-request-after-payment pattern.

**Facilitator as Issuer:**
- Server already trusts facilitator for payment settlement
- No additional trust assumptions or round trips beyond standard x402
- Credential issuance piggybacks on existing settlement response
- Separates issuer (facilitator) from verifier (server) naturally

**Server mediates facilitator communication:**
Following x402 v2 conventions, the client never contacts the facilitator directly. This keeps the architecture clean and ensures servers control their payment flow.

**Deterministic origin tokens:**
The deterministic `origin_token` approach (vs. challenge-based nullifiers) was chosen for:
- Single round-trip (no challenge fetch needed)
- Client-controlled privacy/linkability tradeoff
- Simpler server implementation
- Natural fit with per-origin rate limiting

**Authorization header vs PAYMENT-SIGNATURE:**
ZK proofs use `Authorization: ZKSession` instead of `PAYMENT-SIGNATURE` because:
- ZK proofs are redemption tokens, not payment payloads
- Allows servers to distinguish payment from redemption
- Redemption doesn't require facilitator involvement

---

## Appendix D: x402 v2 Alignment Summary

| x402 v2 Feature | zk-session Alignment |
|-----------------|---------------------|
| `PAYMENT-REQUIRED` header | ✓ Extension in `extensions.zk_session` |
| `PAYMENT-SIGNATURE` header | ✓ Commitment in `extensions.zk_session` |
| `PAYMENT-RESPONSE` header | ✓ Credential in `extensions.zk_session` |
| Server↔Facilitator flow | ✓ Server calls /verify, /settle |
| Client↔Server only | ✓ Client never contacts facilitator |
| Base64-encoded payloads | ✓ Standard encoding |
| `x402Version: 2` | ✓ Used in all payloads |
| CAIP-2 network identifiers | ✓ Used (e.g., `eip155:8453`) |
| Facilitator `/settle` request | Extended with `extensions.zk_session` |
| Facilitator `/settle` response | Extended with credential |

**Intentional deviations:**
- Redemption uses `Authorization` header, not `PAYMENT-SIGNATURE`
- Redemption is a separate request (for privacy), not same-request
- Redemption does not involve facilitator (proof verified locally)


## Transport and size limits

Some proof systems and credential formats can easily exceed common HTTP header field limits. This has already been observed in practice with UltraHonk-style proofs on the order of ~15KB, which can trigger failures in typical reverse proxies and servers when carried in headers.

**Normative guidance:**

1. **Do not assume headers can carry proofs.** Implementations MUST NOT require clients to place full proofs in HTTP headers.
2. **Prefer response bodies for large artifacts.** If issuance returns large credential material (e.g., proof blobs, verification key hashes, transcripts), the server SHOULD return that material in the **response body** as JSON and keep `PAYMENT-RESPONSE` header content minimal (receipt-oriented).
3. **Body fallback is required.** Clients implementing this extension MUST support a body-based transport for:
   - issued credential material returned after settlement, and
   - authorization proofs presented to protected endpoints.
4. **Small header, big body pattern.**
   - Headers MAY be used for small routing / signaling fields only (e.g., extension id, version, or a short handle).
   - Large blobs MUST be placed in the request/response body.

### Recommended envelope for body transport

When returning an issued credential after settlement, the server SHOULD use:

```json
{
  "x402": {
    "payment_response": { /* decoded PAYMENT-RESPONSE receipt fields */ }
  },
  "zk_session": {
    "credential": { /* issued credential material */ }
  }
}
```

When presenting authorization to a protected endpoint, clients SHOULD use:

```json
{
  "zk_session": {
    "authorization": { /* proof / signature / metadata */ }
  }
}
```

Servers MAY still accept `Authorization: ZKSession <base64url(JSON)>` for small authorizations, but MUST support the JSON body form above.

