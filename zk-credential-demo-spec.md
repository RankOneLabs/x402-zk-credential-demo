# x402 Extension: zk-credential

**Extension ID:** `zk-credential`  
**Version:** 0.1.0  
**Status:** Draft  
**Last Updated:** 2026-02-06  
**x402 Compatibility:** v2

---

## 1. Overview

This extension enables **pay-once, redeem-many** access to x402-protected resources using privacy-preserving credentials proved in zero knowledge.

> **Definition:** A `zk-credential` is a payment-bound access credential issued after successful x402 settlement. Clients present ZK proofs of possession to authorize requests without revealing a linkable identifier.

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

## 4. Roles

| Role | Description |
|------|-------------|
| **Client** | Requests protected resources, performs x402 payment, stores credential, proves possession for later requests. |
| **Server** | Protected resource server. Verifies ZK proofs for access control and mediates settlement. |
| **Issuer** | Signs credentials. MAY be the Facilitator (default) or the Server itself. |
| **Verifier** | Validates proofs and authorizes access. Typically the Server or an authorized gateway. Verifiers accept only `service_id` + issuer key combinations they are independently configured to trust; extension advertisements are informational, not authoritative. |

**Note:** In x402 v2, clients communicate only with the server. The server handles facilitator communication. This extension follows that pattern.

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
PHASE 1: Payment + Credential Issuance (standard x402 extension plumbing)
─────────────────────────────────────────────────────────────────────
1. Client → Server:      GET /resource
2. Server → Client:      402 Payment Required
                         PAYMENT-REQUIRED: <base64 PaymentRequired>
                         (includes extensions["zk-credential"] with issuer info)
3. Client → Server:      GET/POST /resource
                         PAYMENT-SIGNATURE: <base64 PaymentPayload>
                         (includes extensions["zk-credential"].info.commitment)
4. Server → Facilitator: POST /settle (PaymentPayload with commitment in extensions)
5. Facilitator → Server: SettleResponse with credential in extensions["zk-credential"]
6. Server → Client:      200 OK
                         PAYMENT-RESPONSE: <base64 SettleResponse>
                         (credential inside SettleResponse.extensions["zk-credential"])

PHASE 2: Private Redemption (body envelope)
─────────────────────────────────────────────────────────────────────
7.  Client → Server:     POST /resource
                         Content-Type: application/json
                         Body: { x402_zk_credential: { proof, public_outputs }, payload: <app body> }
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

### 6.1 Transport Model

This extension uses a **split transport model** with different mechanisms for issuance and presentation:

1. **Issuance (Phase 1):** Standard x402 extension plumbing. Commitment and credential travel inside the existing `PaymentPayload.extensions` and `SettleResponse.extensions` fields, carried by the standard `PAYMENT-SIGNATURE` and `PAYMENT-RESPONSE` headers.
2. **Presentation (Phase 2):** Body envelope. ZK proofs (~15KB for UltraHonk) exceed HTTP header limits; they MUST be carried in the request body.

**Zero custom headers** are used for the entire extension lifecycle. Presence of `x402_zk_credential` in the request body is the canonical signal for redemption.

### 6.2 Header Inventory

All issuance data travels through standard x402 plumbing, and presentation proofs are carried in the request body. **No custom headers** are used.

### 6.3 Content Types and Encoding

| Content-Type | Status | Notes |
|--------------|--------|-------|
| `application/json` | REQUIRED | Base64url-encoded binary fields (no padding) |
| `application/cbor` | OPTIONAL | Raw byte strings for binary data |

**Encoding Rules:**
- **Suite-typed cryptographic objects:** `commitment` and `signature` MUST use the suite-typed string format `<suite-id>:<base64url(bytes)>`.
- **Public keys:** `issuer_pubkey` is raw public-key bytes base64url (no padding), interpreted under the suite in the same object.
- **Other binary fields:** `proof` and `origin_token` are base64url without padding (RFC 4648).
- **Timestamps:** Must be Unix time in seconds (integer).

### 6.4 Request Envelope (Proof Presentation)

Clients present ZK credentials by sending the proof in a body envelope:

```
POST /api/resource HTTP/1.1
Content-Type: application/json
```

```json
{
  "x402_zk_credential": {
    "version": "0.1.0",
    "suite": "pedersen-schnorr-poseidon-ultrahonk",
    "issuer_pubkey": "BAAB...",
    "proof": "<base64url-proof>",
    "current_time": 1707004800,
    "public_outputs": {
      "origin_token": "<base64url-origin-token>",
      "tier": 1
    }
  },
  "payload": <original application body or null>
}
```

The `payload` field contains whatever the application request body would normally be. For requests that originally had no body (e.g., GET-like semantics), `payload` is `null`.

| Field | Required | Description |
|-------|----------|-------------|
| `version` | Yes | Spec version for protocol negotiation |
| `suite` | Yes | Suite identifier so server selects correct verifier |
| `issuer_pubkey` | Yes | Base64url raw public-key bytes; verifier must authorize against local key set |
| `proof` | Yes | Base64url-encoded ZK proof |
| `current_time` | Yes | Unix timestamp used as public input during proof generation; server validates ±60s drift (§11.1) |
| `public_outputs` | Yes | Circuit outputs |
| `payload` | Yes | Original application body, or `null` |

**`public_outputs` fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `origin_token` | Yes | Unlinkable rate-limiting token (circuit output) |
| `tier` | Yes | Access level (circuit output) |

### 6.5 Response: Credential Issuance

The credential is returned inside `SettleResponse.extensions["zk-credential"]`, carried by the standard `PAYMENT-RESPONSE` header. No custom response headers are used.

```
HTTP/1.1 200 OK
PAYMENT-RESPONSE: <base64 SettleResponse>
```

The decoded `SettleResponse` contains the credential in extensions:

```json
{
  "success": true,
  "payer": "0x...",
  "transaction": "0x...",
  "network": "eip155:8453",
  "extensions": {
    "zk-credential": {
      "credential": {
        "suite": "pedersen-schnorr-poseidon-ultrahonk",
        "service_id": "k7VzM_xR9bQ2h1nPfEjw",
        "tier": 1,
        "identity_limit": 1000,
        "expires_at": 1707004800,
        "commitment": "pedersen-schnorr-poseidon-ultrahonk:<base64url-commitment>",
        "signature": "pedersen-schnorr-poseidon-ultrahonk:<base64url-signature>"
      }
    }
  }
}
```

The response body is freed for application use (e.g., the requested resource).

The server's `enrichSettlementResponse` hook (from the x402 `ResourceServerExtension` interface) produces the credential after settlement. The SDK automatically injects it into `SettleResponse.extensions`.
```

### 6.6 Proof Size Expectations

| Proof System | Raw Size | Base64 Size |
|--------------|----------|-------------|
| UltraHonk | ~16 KB | ~22 KB |
| Groth16 | ~200 B | ~270 B |

> **Note:** UltraHonk proofs exceed typical HTTP header limits (8-16 KB). Body transport is required.
> **Recommendation:** Servers SHOULD accept proof bodies up to **64 KB**. Servers MAY set lower limits but MUST return `413 payload_too_large` with the maximum accepted size in the error response.

### 6.7 HTTP Method for Redemption

Requests that would normally be `GET` with no body must be sent as `POST` when carrying ZK credential redemption, because the proof is in the body. The server must accept `POST` for any endpoint that supports ZK credential access.

```
GET  /api/resource              → normal unauthenticated request (gets 402)
POST /api/resource              → ZK credential redemption request
  Body:   { "x402_zk_credential": {...}, "payload": null }
```

The server middleware unwraps the envelope, verifies the proof, and forwards the inner `payload` (or empty body) to the application handler. From the application handler's perspective, it receives a normal request with an attached `tier` value — it never sees the ZK credential envelope.

---

## 7. Extension Advertisement

When returning `402 Payment Required`, servers supporting zk-credential include the extension in `PaymentRequired.extensions["zk-credential"]`. The extension follows the `{ info, schema }` pattern from the x402 SDK:

```json
{
  "x402Version": 2,
  "accepts": [
    {
      "scheme": "exact",
      "network": "eip155:8453",
      "amount": "100000",
      "resource": "https://api.example.com/data",
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

The `schema` field declares what the client is expected to append inside `info` (the commitment). The server's `enrichPaymentRequiredResponse` hook produces this structure.

| Field | Description |
|-------|-------------|
| `version` | Spec version (semver) |
| `credential_suites` | Supported cryptographic suites (see §13) |
| `issuer_suite` | Suite identifier used for issuance |
| `issuer_pubkey` | Base64url raw public-key bytes (informational; verifier authorizes keys locally) |
| `max_credential_ttl` | Optional. Maximum credential lifetime in seconds |
| `service_id` | Required service policy identifier (base64url of 16 random bytes) |

Clients that don't support zk-credential ignore `extensions.zk-credential` and use standard x402.

---

## 8. Credential Issuance

### 8.1 Client Preparation

Before payment, client generates locally (never sent to anyone):
- `nullifier_seed` — random secret
- `blinding_factor` — random blinding value

Client computes:
- `commitment = Commit(nullifier_seed, blinding_factor)` — hiding commitment

### 8.2 Payment Request with Commitment

Client appends the commitment inside `PaymentPayload.extensions["zk-credential"].info.commitment`, following the x402 SDK's extension pattern where client data is added inside `info` alongside the server's declared fields. Only the standard `PAYMENT-SIGNATURE` header is used:

```
GET /api/resource HTTP/1.1
PAYMENT-SIGNATURE: <base64 PaymentPayload>
```

The decoded `PaymentPayload.extensions["zk-credential"]` contains:

```json
{
  "info": {
    "version": "0.1.0",
    "credential_suites": ["pedersen-schnorr-poseidon-ultrahonk"],
    "issuer_suite": "pedersen-schnorr-poseidon-ultrahonk",
    "issuer_pubkey": "BAAB...",
    "max_credential_ttl": 86400,
    "service_id": "k7VzM_xR9bQ2h1nPfEjw",
    "commitment": "pedersen-schnorr-poseidon-ultrahonk:<base64url-commitment-point>"
  },
  "schema": { "..." }
}
```

The `commitment` field is a suite-typed string encoding the Pedersen commitment point. The client echoes the server's extension and adds `commitment` inside `info`.

### 8.3 Server Forwards to Facilitator

Server calls facilitator's `/settle` endpoint:

```json
{
  "payment": { /* from request */ },
  "paymentRequirements": { /* from server config */ },
  "extensions": {
    "zk-credential": {
      "commitment": "pedersen-schnorr-poseidon-ultrahonk:<base64url-commitment>"
    }
  }
}
```

### 8.4 Facilitator Response with Credential

Facilitator returns credential in settlement response body:

```json
{
  "payment_receipt": {
    "status": "settled",
    "txHash": "0x...",
    "network": "eip155:8453"
  },
  "extensions": {
    "zk-credential": {
      "credential": {
        "suite": "pedersen-schnorr-poseidon-ultrahonk",
        "service_id": "k7VzM_xR9bQ2h1nPfEjw",
        "tier": 1,
        "identity_limit": 1000,
        "expires_at": 1707004800,
        "commitment": "pedersen-schnorr-poseidon-ultrahonk:<base64url-commitment>",
        "signature": "pedersen-schnorr-poseidon-ultrahonk:<base64url-signature>"
      }
    }
  }
}
```

### 8.5 Server Returns Credential to Client

After settlement, the server's `enrichSettlementResponse` hook reads the commitment from `context.paymentPayload.extensions["zk-credential"].info.commitment`, signs a credential, and returns it. The SDK injects it into `SettleResponse.extensions["zk-credential"]`. Only the standard `PAYMENT-RESPONSE` header is used:

```
HTTP/1.1 200 OK
PAYMENT-RESPONSE: <base64 SettleResponse>
```

The client decodes the `PAYMENT-RESPONSE` header and reads `settleResponse.extensions["zk-credential"].credential`. The response body is freed for application use.

> **Note:** Servers MAY include the requested resource in the Phase 1 response body. Clients seeking maximum privacy MAY discard the Phase 1 response data and re-request via Phase 2 using an unlinkable proof.

### 8.6 Credential Fields

| Field | Required | Description |
|-------|----------|-------------|
| `suite` | Yes | Cryptographic suite used |
| `service_id` | Yes | Identifies the service policy domain |
| `tier` | Yes | Access level (0, 1, 2, ...) — derived from payment amount |
| `identity_limit` | Yes | Maximum distinct identities derivable from credential |
| `expires_at` | Yes | Unix timestamp of expiration |
| `commitment` | Yes | Suite-typed commitment string |
| `signature` | Yes | Suite-typed issuer signature over all fields |

**Facilitator MUST NOT** store or log commitment-to-payment mappings beyond immediate operational needs.

---

## 9. Credential Identity (Private Redemption)

### 9.1 Transport

Clients present credentials via `POST` with a body envelope:

```
POST /api/resource HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "x402_zk_credential": {
    "version": "0.1.0",
    "suite": "pedersen-schnorr-poseidon-ultrahonk",
    "issuer_pubkey": "BAAB...",
    "proof": "<base64url-proof>",
    "current_time": 1707004800,
    "public_outputs": {
      "origin_token": "<base64url-origin-token>",
      "tier": 1
    }
  },
  "payload": null
}
```

The `payload` field contains whatever the application request body would normally be (or `null` for requests with no body). The server middleware unwraps this and forwards it to the application handler.

### 9.2 Proof Public Inputs

The server constructs public inputs from its own configuration and the client-provided `current_time`:

| Input | Source |
|-------|--------|
| `service_id` | Server configuration (see §10.4) |
| `current_time` | From client's `x402_zk_credential.current_time`; validated within ±60s of server clock (§11.1) |
| `origin_id` | Computed from request URL per §10 |
| `issuer_pubkey` | Provided in the request; verifier must authorize against local key set |

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
canonical_origin = canonicalize(request_url)
stringToField(s) = SHA-256(UTF-8(s)) mod p   (where p is the BN254 scalar field order)
origin_id = stringToField(canonical_origin)
```

### 10.2 Canonicalization Algorithm

Given a request URL, produce `canonical_origin` via the following deterministic steps:

1. **Parse** the URL into RFC 3986 components: `scheme`, `host`, `port`, `path`. **Reject** if parsing fails.
2. **Scheme**: lowercase (e.g. `HTTPS` → `https`).
3. **Host**: lowercase. Implementations **MUST** convert Unicode hostnames to Punycode (IDNA) before lowercasing.
4. **Port**: omit default ports (`80` for `http`, `443` for `https`); include non-default ports.
5. **Path**: if empty, set to `/`.
6. **Dot-segment removal**: normalize `.` and `..` segments per RFC 3986 §5.2.4.
7. **Query and fragment**: **MUST** be excluded.
8. **Percent-encoding**: use the path as produced by the URL parser after dot-segment removal; do **not** decode/re-encode percent escapes.
9. **Assemble**: `canonical_origin = scheme + "://" + host + port_suffix + normalized_path` where `port_suffix` is `":" + port` only when non-default.

### 10.3 Test Vectors

| Input URL | `canonical_origin` |
|---|---|
| `https://API.Example.COM/v1/data` | `https://api.example.com/v1/data` |
| `https://api.example.com:443/v1/data` | `https://api.example.com/v1/data` |
| `http://api.example.com:8080/v1/data` | `http://api.example.com:8080/v1/data` |
| `https://api.example.com` | `https://api.example.com/` |
| `https://api.example.com/a/b/../c` | `https://api.example.com/a/c` |
| `https://api.example.com/a/./b` | `https://api.example.com/a/b` |
| `https://api.example.com/v1/data?key=val#frag` | `https://api.example.com/v1/data` |
| `https://api.example.com/hello%20world` | `https://api.example.com/hello%20world` |

### 10.4 Security Binding

Credentials/proofs MUST bind to:
- **Audience** — via `service_id` + `origin_id`
- **Scope** — via `origin_id`
- **Expiry** — via `expires_at`
- **Tier** — if applicable

> **Security Note:** Without host in `origin_id`, proofs can be replayed across servers sharing an issuer key.

### 10.4 Service ID

`service_id` identifies the logical policy domain for which verifiers enforce rules, not a specific physical server or deployment.

**Required format:** base64url of 16 random bytes (128 bits), no padding. Issuers **MUST** generate `service_id` using a cryptographically secure RNG.

`service_id` is stable for a service across key rotations unless the service intentionally changes identity. It MUST match the credential `service_id` presented in proofs. Different `origin_id` values provide per-endpoint granularity within a single `service_id`.

---

## 11. Proof Statement

The ZK proof MUST prove:

1. The client holds an issuer-signed credential for `service_id`.
2. The credential was signed by the `issuer_pubkey` provided in the presentation.
3. `current_time <= expires_at`.
4. Credential `tier` satisfies server policy.
5. The client's chosen derivation index `i` satisfies `0 <= i < identity_limit`.
6. `origin_token` is deterministically derived from private credential material, `origin_id`, and derivation index `i`.
7. `origin_id` is correctly bound (prevents replay across origins).
8. The proof outputs include `(origin_token, tier)`.

Verifiers **MUST** verify the proof using the provided `issuer_pubkey` and **MUST** ensure that the key is authorized for the associated `service_id` by local policy.

### 11.1 Clock Skew Tolerance

The circuit uses `current_time` as a public input. The client chooses this value at proof generation time and transmits it in `x402_zk_credential.current_time` (§6.4). The server uses the client-provided value to reconstruct public inputs for proof verification, but MUST validate it against the server's own clock:

- Servers MUST reject requests where `|x402_zk_credential.current_time - server_clock| > 60 seconds`.
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

A credential suite defines the complete cryptographic stack. Suite identifiers are opaque labels mapping to specifications. A suite fully specifies the proving system (SNARK/STARK), verifier algorithm/parameters, signature scheme, and hash functions.

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

Suite-specific cryptographic objects **MUST** use the suite-typed string format:

```
"<suite-id>:<base64url(bytes)>"
```

All public keys are encoded as raw bytes base64url (no padding) in a `*_pubkey` field and are interpreted under the suite indicated by the nearest `suite` / `*_suite` field. Verifiers **MUST** reject keys that are not valid encodings for the suite.

Examples:
- Adjacent-field public key: `"issuer_suite": "pedersen-schnorr-poseidon-ultrahonk", "issuer_pubkey": "BAAB..."`
- Suite-typed commitment: `"pedersen-schnorr-poseidon-ultrahonk:BAAB..."`
- Suite-typed signature: `"pedersen-schnorr-poseidon-ultrahonk:AQID..."`

Other binary fields (`proof`, `origin_token`) use plain base64url without suite prefix.

---

## 14. Error Responses

### 14.1 Error Codes

| Code | HTTP | Meaning |
|------|------|---------|
| `credential_missing` | 402 | No payment or credential provided |
| `tier_insufficient` | 402 | Tier below requirement |
| `unsupported_version` | 400 | Version not supported |
| `unsupported_suite` | 400 | Suite not supported |
| `invalid_proof` | 400 | Proof verification failed (includes expired credentials, see note below) |
| `payload_too_large` | 413 | Proof body exceeds size limit |
| `unsupported_media_type` | 415 | Content-Type not supported |
| `rate_limited` | 429 | Origin token rate limited |

> **Note:** Because `expires_at` is a private input enforced inside the circuit, the server cannot distinguish an expired credential from other proof failures. Both result in `invalid_proof`. Clients SHOULD track credential expiry locally and re-enter the payment flow before attempting to prove with an expired credential.

### 14.2 Error Bodies

Error response bodies are implementation-defined. Servers MAY include additional diagnostic fields, but clients MUST rely on the HTTP status and error code semantics above for interoperability.

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

Server steps for requests with `x402_zk_credential` in the request body:

1. Parse `x402_zk_credential` from request body
2. Extract `suite`, `issuer_pubkey`, and `proof`
3. If unsupported suite → `400 unsupported_suite`
4. If body too large → `413 payload_too_large` (include `max_body_bytes`)
5. Verify `issuer_pubkey` is authorized for the `service_id` by local policy; if not → `400 invalid_proof`
6. Compute `origin_id` from request URL per §10
7. Extract `current_time` from client's `x402_zk_credential.current_time`
8. If `|current_time - server_clock| > 60s` → `400 invalid_proof` (clock drift exceeded)
9. Construct public inputs: `(service_id, current_time, origin_id, issuer_pubkey)`
10. Verify proof locally (no facilitator call needed)
11. If invalid → `400 invalid_proof`
12. Extract outputs: `(origin_token, tier)`
13. Check rate limit for `origin_token`
14. If exceeded → `429 rate_limited`
15. Check `tier` meets endpoint requirement
16. If insufficient → `402 tier_insufficient`
17. Unwrap `payload` from envelope into `req.body` for downstream handler
18. Allow request

Server steps for requests without `x402_zk_credential` in the body:

1. Check for `PAYMENT-SIGNATURE` header
2. If present → process as standard x402 payment. If `PaymentPayload.extensions["zk-credential"].info.commitment` exists, issue credential via `enrichSettlementResponse` hook
3. If absent → return `402` with payment requirements and `zk-credential` extension

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

### 17.2 Denial of Service (DoS) Guidance

Verification is computationally expensive. Servers SHOULD perform cheap pre-checks before verification:
- Enforce `Content-Length` limits (e.g., 64KB).
- Validate `current_time` skew (±60s).
- Check `suite` support (fast fail on unsupported suites).
- Apply rate limits based on IP or other factors before parsing the proof.

---

## 18. Verification Keys: Distribution & Rollover

- Presentations **MUST** include `issuer_pubkey`.
- Verifiers **MUST** accept only presentations whose `issuer_pubkey` is authorized by verifier policy for the `service_id` (e.g., local configuration or trusted key set).
- Issuers **MAY** rotate keys at any time; verifiers **SHOULD** overlap old and new keys long enough to avoid breaking valid credentials before expiry.

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
- Extension data in `extensions.zk-credential`
- Uses CAIP-2 network identifiers (e.g., `eip155:8453` for Base)
- Server↔Facilitator communication follows canonical v2 flow
- Requires facilitator support for zk-credential extension

### 20.2 Facilitator Requirements

This extension requires a facilitator that:
- Accepts `extensions.zk-credential.commitment` in settle requests
- Returns `extensions.zk-credential.credential` in settle responses
- Does not log commitment-to-payment mappings

### 20.3 Backwards Compatibility

- Non-implementing clients ignore `extensions.zk-credential` and use standard x402
- Non-implementing servers return standard x402 responses
- Multiple suites can coexist; client picks from server's list

### 20.4 Naming Convention

- Extension ID (string identifier): `zk-credential`
- JSON object key: `zk-credential`

---

## 21. Conformance

An implementation conforms to this specification if it:

1. Advertises support via `extensions["zk-credential"]` in `PaymentRequired` (using `{ info, schema }` pattern)
2. Accepts commitments inside `PaymentPayload.extensions["zk-credential"].info.commitment`
3. Returns credentials inside `SettleResponse.extensions["zk-credential"].credential` via standard `PAYMENT-RESPONSE` header
4. Accepts proofs in request body via `x402_zk_credential` envelope
5. Forwards commitment to facilitator during settlement
6. Verifies ZK proofs per §15
7. Enforces rate limiting per §12
8. Returns correct error codes per §14
9. Supports at least one registered suite
10. Computes `origin_id` per §10
11. Unwraps `payload` from envelope for downstream handlers
12. Uses **zero** custom headers for the entire extension (only standard x402 headers for issuance)

---

## Appendix A: Credential Structure (Informative)

```
Credential {
  // Signed by issuer
  service_id: Field
  tier: Field
  identity_limit: Field
  expires_at: Field
  commitment: Point  // Suite-typed commitment
  signature: Bytes  // Suite-typed signature
  
  // Client secrets (never sent)
  nullifier_seed: Field
  blinding_factor: Field
}
```

---

## Appendix B: Example Flow

```
# ═══════════════════════════════════════════════════════════════════
# PHASE 1: Payment + Credential Issuance (standard x402 plumbing)
# ═══════════════════════════════════════════════════════════════════

# 1. Client requests resource
GET /api/data HTTP/1.1
Host: api.example.com

# 2. Server returns 402 with zk-credential extension
#    PaymentRequired.extensions["zk-credential"] populated by
#    enrichPaymentRequiredResponse hook
HTTP/1.1 402 Payment Required
PAYMENT-REQUIRED: <base64 PaymentRequired>

#    Decoded PaymentRequired:
#    {
#      "x402Version": 2,
#      "accepts": [{ "scheme": "exact", "network": "eip155:8453", ... }],
#      "extensions": {
#        "zk-credential": {
#          "info": {
#            "version": "0.1.0",
#            "credential_suites": ["pedersen-schnorr-poseidon-ultrahonk"],
#            "issuer_pubkey": "BAAB...",
#            "issuer_suite": "pedersen-schnorr-poseidon-ultrahonk",
#            "service_id": "k7VzM_xR9bQ2h1nPfEjw"
#          },
#          "schema": { ... }
#        }
#      }
#    }

# 3. Client sends payment + commitment (single standard header)
#    Client echoes extension and adds commitment inside info
GET /api/data HTTP/1.1
Host: api.example.com
PAYMENT-SIGNATURE: <base64 PaymentPayload>

#    Decoded PaymentPayload.extensions["zk-credential"].info includes:
#    { ...server_fields, "commitment": "pedersen-schnorr-poseidon-ultrahonk:<base64url-commitment>" }

# 4. Server → Facilitator: POST /settle
#    PaymentPayload passes through with extensions intact

# 5. Facilitator → Server:
#    SettleResponse with credential in extensions["zk-credential"].credential

# 6. Server returns payment response (standard header, credential inside)
#    enrichSettlementResponse hook injects credential into SettleResponse.extensions
HTTP/1.1 200 OK
PAYMENT-RESPONSE: <base64 SettleResponse>

#    Decoded SettleResponse.extensions["zk-credential"]:
#    { "credential": { "suite": "...", ... } }

# ═══════════════════════════════════════════════════════════════════
# PHASE 2: Private Redemption (body envelope)
# ═══════════════════════════════════════════════════════════════════

# 7. Client generates ZK proof and requests resource
POST /api/data HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "x402_zk_credential": {
    "version": "0.1.0",
    "suite": "pedersen-schnorr-poseidon-ultrahonk",
    "issuer_pubkey": "BAAB...",
    "proof": "<base64url-proof>",
    "current_time": 1707004800,
    "public_outputs": {
      "origin_token": "<base64url-origin-token>",
      "tier": 1
    }
  },
  "payload": null
}

# 8. Server verifies proof locally (no facilitator call)
#    Server unwraps payload into req.body for application handler

# 9. Server returns resource
HTTP/1.1 200 OK
Content-Type: application/json

{"data": "response via private redemption"}
```

---

## Appendix C: Rationale

**Body transport for presentation:**
UltraHonk proofs (~16KB raw, ~22KB base64) exceed HTTP header limits (8-16KB) in most gateways. Body transport is required for practical deployment.

**POST for redemption:**
Since proofs are in the body, GET is not appropriate. POST with proof enables stateless verification. The server must accept POST for any endpoint that supports ZK credential access.

**Two-phase flow for privacy:**
If credential redemption occurred in the same request as payment, the server would trivially link payment identity to access. Separating payment (Phase 1) from redemption (Phase 2) is what enables unlinkability.

**Issuer selection:**
- Issuer MAY be the Facilitator (default) or the Server itself
- Verifiers authorize issuer keys via local policy, independent of extension advertisement
- Credential issuance still piggybacks on existing settlement response

**`expires_at` checked inside circuit:**
The circuit checks `expires_at >= current_time` internally. This keeps `expires_at` private (not leaked as a public output) while still enforcing freshness: the client-provided `x402_zk_credential.current_time` is a public input to the circuit, while `expires_at` remains private, and the server validates that this client-supplied time is within an acceptable drift of its own clock.


