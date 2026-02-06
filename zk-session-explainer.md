# ZK Session Credentials for x402

## Problem
Core x402 is intentionally simple: access is paid per request. A client requests a protected endpoint, receives a `402 Payment Required` challenge, then retries with a payment payload. The server verifies/settles the payment and returns the protected response in that same paid request. There is no reusable session primitive in baseline x402.

When implementers want “pay once, redeem many times” (subscriptions, bundles, day passes, metered plans, etc.), they typically add a separate session mechanism on top: API keys, bearer tokens, or sign-in flows (often SIWx-style). These mechanisms introduce a stable identifier that links requests together. Even if the payment step is privacy-preserving (e.g., via z402), the added session layer can still make usage linkable.

## Approach
ZK Session Credentials extend the x402 flow by adding an issuance step after settlement and a proof-based presentation step for subsequent requests.

### Phase 1: Standard x402 payment + credential issuance
1. Client requests a protected resource and receives an x402 payment challenge.
2. Client retries with the x402 payment payload; server verifies/settles via the facilitator.
3. After settlement, a facilitator-signed session credential is returned (forwarded through the server to the client).

The credential is short-lived and bounded, and can include:
- `service_id` binding (prevents cross-service replay)
- `tier` (access level derived from payment amount)
- `issued_at`, `expires_at`
- optional `max_presentations` or other usage limits
- facilitator signature over the credential fields

### Phase 2: ZK presentation for subsequent requests
4. Later requests do not resend the payment payload and do not use a stable session token.
5. Instead, the client provides a zero-knowledge proof that it holds a valid credential matching the endpoint’s requirements (service binding, tier, expiry, usage constraints).
6. The server verifies the proof locally, without a facilitator call per request.

This provides a reusable access primitive without turning “session” into an identifier.

## Replay prevention and rate limiting
To support replay prevention and usage constraints, the proof derives an `origin_token`, for example:

`origin_token = hash(nullifier_seed, origin_id, presentation_index)`

The server tracks `origin_token` values to enforce constraints (e.g., prevent reuse, rate limit per origin). The client can control linkability behavior by how it uses `presentation_index` and `origin_id` across requests/endpoints.

## Transport considerations
Proof and credential artifacts can exceed common HTTP header limits (proof sizes around the ~10–20KB range have already caused integration failures). The extension therefore defines a body-based transport option and recommends avoiding “large header” designs for proofs. In the body-based option, the proof and credential are carried in the HTTP request body (for example, as a JSON object with a dedicated `zk_session` field), while headers remain small and conventional. The exact wire format is defined in the x402 ZK Session Credentials transport section of the spec, which implementers SHOULD follow for interoperability.

## Status
- A working demo exercises the flow (x402 payment → credential issuance → proof-based access).
- The spec is ready for review, with emphasis on protocol shape, interoperability, and transport constraints (including proof sizing and fallback mechanisms).
