/**
 * Common types for cryptographic operations
 * Compliant with x402 zk-session spec v0.1.0
 * 
 * Uses @x402/core types for payment layer, extends with zk_session types.
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
// ZK Session Credential Types (spec §7.3, Appendix A)
// =============================================================================

/** Supported cryptographic schemes */
export type ZKSessionScheme = 'pedersen-schnorr-bn254';

/** Credential as signed by facilitator (spec §7.3) */
export interface SignedCredential {
  scheme: ZKSessionScheme;
  serviceId: bigint;
  tier: number;
  maxPresentations: number;
  issuedAt: number;
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
// x402 Protocol Types with ZK Session Extension (spec §6, §7, §13)
// =============================================================================

/** zk_session extension in 402 response (spec §6) */
export interface ZKSessionExtension {
  version: '0.1';
  schemes: ZKSessionScheme[];
  facilitator_pubkey: string; // scheme-prefixed: "pedersen-schnorr-bn254:0x..."
  facilitator_url?: string;   // URL to send settlement requests
}

/**
 * Extended x402 PaymentRequired with zk_session extension
 * This is what the API returns for 402 Payment Required responses.
 */
export interface X402WithZKSessionResponse extends PaymentRequired {
  extensions: {
    zk_session: ZKSessionExtension;
  } & Record<string, unknown>;
}

/**
 * @deprecated Use X402WithZKSessionResponse instead
 * Legacy x402 response format - kept for backward compatibility during migration
 */
export interface X402Response {
  x402: {
    payment_requirements: X402PaymentRequirements;
    extensions: {
      zk_session: ZKSessionExtension;
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

/** Payment request to facilitator with zk_session commitment (spec §7.2) */
export interface X402PaymentRequest {
  payment: unknown; // x402 payment proof (opaque to zk-session layer)
  zk_session: {
    commitment: string; // scheme-prefixed: "pedersen-schnorr-bn254:0x..."
  };
}

/** Credential in wire format (JSON-serializable) */
export interface CredentialWireFormat {
  scheme: ZKSessionScheme;
  service_id: string;
  tier: number;
  max_presentations: number;
  issued_at: number;
  expires_at: number;
  commitment: string; // hex, NO scheme prefix
  signature: string;  // hex-encoded
}

/** Payment response from facilitator (spec §7.3) */
export interface X402PaymentResponse {
  payment_receipt: unknown; // x402 receipt (opaque to zk-session layer)
  zk_session: {
    credential: CredentialWireFormat;
  };
}

// =============================================================================
// Error Types (spec §13)
// =============================================================================

/** ZK session error codes per spec §13 */
export type ZKSessionErrorCode =
  | 'unsupported_zk_scheme'   // 400
  | 'invalid_zk_proof'        // 401
  | 'proof_expired'           // 401
  | 'tier_insufficient'       // 403
  | 'rate_limited';           // 429

/** Error response body */
export interface ZKSessionError {
  error: ZKSessionErrorCode;
  message?: string;
}

/** Map error codes to HTTP status */
export const ERROR_CODE_TO_STATUS: Record<ZKSessionErrorCode, number> = {
  unsupported_zk_scheme: 400,
  invalid_zk_proof: 401,
  proof_expired: 401,
  tier_insufficient: 403,
  rate_limited: 429,
};

// =============================================================================
// Utility Functions
// =============================================================================

/** Parse scheme-prefixed string (e.g., "pedersen-schnorr-bn254:0x...") */
export function parseSchemePrefix(prefixed: string): { scheme: ZKSessionScheme; value: string } {
  const colonIdx = prefixed.indexOf(':');
  if (colonIdx === -1) {
    throw new Error('Invalid scheme-prefixed string: missing colon');
  }
  const scheme = prefixed.slice(0, colonIdx) as ZKSessionScheme;
  const value = prefixed.slice(colonIdx + 1);
  if (scheme !== 'pedersen-schnorr-bn254') {
    throw new Error(`Unsupported scheme: ${scheme}`);
  }
  return { scheme, value };
}

/** Create scheme-prefixed string */
export function addSchemePrefix(scheme: ZKSessionScheme, value: string): string {
  return `${scheme}:${value}`;
}
