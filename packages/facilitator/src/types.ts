/**
 * Types for credential issuance
 * Compliant with x402 zk-session spec v0.1.0
 */

import type {
  X402PaymentRequest,
  X402PaymentResponse,
  CredentialWireFormat,
  ZKSessionScheme,
  PaymentPayload,
  PaymentRequirements,
} from '@demo/crypto';

// Re-export for convenience
export type { X402PaymentRequest, X402PaymentResponse, CredentialWireFormat, PaymentPayload, PaymentRequirements };

/** 
 * Settlement request (spec §7.2)
 * x402 v2 format with signed payment payload
 */
export interface SettlementRequest {
  /** x402 v2 payment payload with EIP-3009 authorization */
  payment: PaymentPayload;
  /** Payment requirements from the 402 response */
  paymentRequirements: PaymentRequirements;
  /** ZK session extension with scheme-prefixed commitment */
  zk_session: {
    /** Scheme-prefixed commitment: "pedersen-schnorr-bn254:0x..." */
    commitment: string;
  };
}

/** 
 * Settlement response (spec §7.3)
 * Maps to X402PaymentResponse
 */
export interface SettlementResponse {
  /** x402 payment receipt */
  payment_receipt: {
    status: 'settled';
    txHash?: string;
    amountUSDC: number;
  };
  /** ZK session credential */
  zk_session: {
    credential: CredentialWireFormat;
  };
}

/** Verified payment result */
export interface PaymentResult {
  valid: boolean;
  amountUSDC: number;
  payer: string;
  txHash?: string;
}

// =============================================================================
// Legacy types (deprecated, for backward compatibility during migration)
// =============================================================================

/** @deprecated Use SettlementRequest instead */
export interface IssuanceRequest {
  paymentProof: {
    txHash?: string;
    facilitatorReceipt?: string;
    mock?: {
      amountUSDC: number;
      payer: string;
    };
  };
  userCommitment: {
    x: string;
    y: string;
  };
}

/** @deprecated Use SettlementResponse instead */
export interface IssuanceResponse {
  credential: {
    serviceId: string;
    tier: number;
    maxPresentations: number;
    issuedAt: number;
    expiresAt: number;
    userCommitment: {
      x: string;
      y: string;
    };
    signature: {
      r: { x: string; y: string };
      s: string;
    };
    issuerPubkey: {
      x: string;
      y: string;
    };
  };
}
