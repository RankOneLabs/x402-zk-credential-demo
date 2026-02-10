/**
 * Types for credential issuance
 * Compliant with x402 zk-credential spec v0.1.0
 */

import type {
  X402PaymentRequest,
  X402PaymentResponse,
  CredentialWireFormat,
  PaymentPayload,
  PaymentRequirements,
} from '@demo/crypto';

// Re-export for convenience
export type { X402PaymentRequest, X402PaymentResponse, CredentialWireFormat, PaymentPayload, PaymentRequirements };

/** 
 * Settlement request (spec §8.3)
 * x402 v2 format with signed payment payload
 */
export interface SettlementRequest {
  /** x402 v2 payment payload with EIP-3009 authorization */
  payment: PaymentPayload;
  /** Payment requirements from the 402 response */
  paymentRequirements: PaymentRequirements;
  /** ZK credential extension with suite-prefixed commitment */
  extensions: {
    zk_credential: {
      /** Suite-prefixed commitment: "pedersen-schnorr-poseidon-ultrahonk:0x..." */
      commitment: string;
    };
  };
}

/** 
 * Settlement response (spec §8.4)
 * Maps to X402PaymentResponse
 */
export interface SettlementResponse {
  /** x402 payment receipt */
  payment_receipt: {
    status: 'settled';
    txHash?: string;
    amountUSDC: number;
  };
  /** ZK credential */
  extensions: {
    zk_credential: {
      credential: CredentialWireFormat;
    };
  };
}

/** Verified payment result */
export interface PaymentResult {
  valid: boolean;
  amountUSDC: number;
  payer: string;
  txHash?: string;
}
