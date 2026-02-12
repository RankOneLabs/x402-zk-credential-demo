/**
 * Common types for cryptographic operations
 * Compliant with x402 zk-credential spec v0.1.0
 * 
 * Uses @x402/core types for payment layer, extends with zk-credential types.
 */

// Re-export x402 core types for convenience
export type {
  PaymentRequired,
  PaymentRequirements,
  PaymentPayload,
  VerifyResponse,
  SettleResponse,
  Network,
} from '@x402/core/types';

import type {
  PaymentRequired,
  PaymentRequirements,
} from '@x402/core/types';

// =============================================================================
// Core Cryptographic Types
// =============================================================================

/** A point on the BN254 curve */
export interface Point {
  x: bigint;
  y: bigint;
}

/** A Schnorr signature */
export interface SchnorrSignature {
  r: Point;
  s: bigint;
}

/** A Pedersen commitment with opening */
export interface Commitment {
  point: Point;
  secret: bigint;
  blinding: bigint;
}

// =============================================================================
// ZK Credential Types (spec §8, Appendix A)
// =============================================================================

/** Supported credential suites */
export type ZKCredentialSuite =
  | 'pedersen-schnorr-poseidon-ultrahonk'
  | 'pedersen-schnorr-poseidon-groth16';

/** Credential as signed by facilitator (spec §7.3) */
export interface SignedCredential {
  suite: ZKCredentialSuite;
  service_id: string; // base64url-encoded
  identityLimit: number;
  expiresAt: number;
  userCommitment: Point;
  signature: SchnorrSignature;
}

/** Full credential with user secrets (never sent to facilitator) */
export interface FullCredential extends SignedCredential {
  nullifierSeed: bigint;
  blindingFactor: bigint;
}

/** Public inputs to the circuit (spec §8.2) */
export interface PublicInputs {
  serviceId: bigint;
  currentTime: number;
  originId: bigint;
  issuerPubkeyX: bigint;
  issuerPubkeyY: bigint;
}

/** Public outputs from the circuit (spec §8.3) */
export interface ProofOutputs {
  originToken: bigint;
  tier: number;
}

// =============================================================================
// x402 Protocol Types with ZK Credential Extension (spec §6-9, §14)
// =============================================================================

/** zk-credential extension info in 402 response (spec §7) */
export interface ZKCredentialExtensionInfo {
  version: '0.1.0';
  credential_suites: ZKCredentialSuite[];
  issuer_suite: ZKCredentialSuite;
  issuer_pubkey: string; // base64url raw pubkey bytes
  max_credential_ttl?: number;
  service_id: string; // base64url(16 random bytes)
}

/** zk-credential extension schema in 402 response (spec §7) */
export interface ZKCredentialExtensionSchema {
  $schema: string;
  type: 'object';
  properties: {
    commitment: {
      type: 'string';
      description: string;
    };
  };
}

/** zk-credential extension in 402 response (spec §7) */
export interface ZKCredentialExtension {
  info: ZKCredentialExtensionInfo;
  schema: ZKCredentialExtensionSchema;
}

/**
 * Extended x402 PaymentRequired with zk-credential extension
 * This is what the API returns for 402 Payment Required responses.
 */
export interface X402WithZKCredentialResponse extends PaymentRequired {
  extensions: {
    'zk-credential': ZKCredentialExtension;
  } & Record<string, unknown>;
}

/**
 * @deprecated Use X402WithZKCredentialResponse instead
 * Legacy x402 response format - kept for backward compatibility during migration
 */
export interface X402Response {
  x402: {
    payment_requirements: X402PaymentRequirements;
    extensions: {
      'zk-credential': ZKCredentialExtension;
    };
  };
}

/**
 * @deprecated Use PaymentRequirements from @x402/core instead
 * Legacy payment requirements type
 */
export interface X402PaymentRequirements {
  amount: string;
  asset: string;
  facilitator: string;
}

/** Payment request to facilitator with zk-credential commitment (spec §8.3) */
export interface X402PaymentRequest {
  x402Version: 2;
  payment: unknown; // x402 payment proof (opaque to zk-credential layer)
  extensions: {
    'zk-credential': {
      commitment: string; // suite-prefixed: "pedersen-schnorr-poseidon-ultrahonk:<base64url>"
    };
  };
}

/** Credential in wire format (JSON-serializable) */
export interface CredentialWireFormat {
  suite: ZKCredentialSuite;
  service_id: string;
  tier: number;
  identity_limit: number;
  expires_at: number;
  commitment: string; // suite-prefixed: "pedersen-schnorr-poseidon-ultrahonk:<base64url>"
  signature: string;  // suite-prefixed: "pedersen-schnorr-poseidon-ultrahonk:<base64url>"
}

/** Payment response from facilitator (spec §8.4) */
export interface X402PaymentResponse {
  x402Version: 2;
  payment_receipt: unknown; // x402 receipt (opaque to zk-credential layer)
  extensions: {
    'zk-credential': {
      credential: CredentialWireFormat;
    };
  };
}

// =============================================================================
// Redemption Transport Types
// =============================================================================

/**
 * Body envelope for presentation requests.
 * The proof is too large for headers (~15KB), so it goes in the body.
 */
export interface ZkCredentialPresentationEnvelope {
  x402_zk_credential: {
    version: '0.1.0';
    suite: ZKCredentialSuite;
    issuer_pubkey: string; // base64url raw pubkey bytes
    proof: string;          // base64url
    current_time: number;
    public_outputs: {
      origin_token: string;
      tier: number;
    };
  };
  payload: unknown | null;  // original application body, or null for GET-like
}

// =============================================================================
// Error Types (spec §14)
// =============================================================================

/** ZK credential error codes per spec §14 */
export type ZKCredentialErrorCode =
  | 'credential_missing'      // 402
  | 'tier_insufficient'       // 402
  | 'unsupported_version'     // 400
  | 'unsupported_suite'       // 400
  | 'invalid_proof'           // 400
  | 'payload_too_large'       // 413
  | 'unsupported_media_type'  // 415
  | 'rate_limited'            // 429
  | 'not_found'               // 404
  | 'service_unavailable'     // 503
  | 'server_error';           // 500

/** 
 * Standardized Error Envelope (spec §14)
 * All 4xx/5xx responses MUST use this format.
 */
export interface ZKCredentialErrorResponse {
  error: ZKCredentialErrorCode;
  message?: string;
  details?: Record<string, unknown>;
}

/** Error response body */
export interface ZKCredentialError {
  error: ZKCredentialErrorCode;
  message?: string;
}

/** Map error codes to HTTP status */
export const ERROR_CODE_TO_STATUS: Record<ZKCredentialErrorCode, number> = {
  credential_missing: 402,
  tier_insufficient: 402,
  unsupported_version: 400,
  unsupported_suite: 400,
  invalid_proof: 400,
  payload_too_large: 413,
  unsupported_media_type: 415,
  rate_limited: 429,
  not_found: 404,
  service_unavailable: 503,
  server_error: 500,
};

// =============================================================================
// Utility Functions
// =============================================================================

/** Parse suite-prefixed string (e.g., "pedersen-schnorr-poseidon-ultrahonk:<base64url>") */
export function parseSchemePrefix(prefixed: string): { scheme: ZKCredentialSuite; value: string } {
  const colonIdx = prefixed.indexOf(':');
  if (colonIdx === -1) {
    throw new Error('Invalid scheme-prefixed string: missing colon');
  }
  const scheme = prefixed.slice(0, colonIdx) as ZKCredentialSuite;
  const value = prefixed.slice(colonIdx + 1);
  if (
    scheme !== 'pedersen-schnorr-poseidon-ultrahonk' &&
    scheme !== 'pedersen-schnorr-poseidon-groth16'
  ) {
    throw new Error(`Unsupported scheme: ${scheme}`);
  }
  return { scheme, value };
}

/** Create scheme-prefixed string */
export function addSchemePrefix(scheme: ZKCredentialSuite, value: string): string {
  return `${scheme}:${value}`;
}

// Key discovery is out of scope for this extension.
