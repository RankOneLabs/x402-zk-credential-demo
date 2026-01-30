/**
 * Types for credential issuance
 */

/** Request to issue a credential */
export interface IssuanceRequest {
  /** Proof of x402 payment (transaction hash or facilitator receipt) */
  paymentProof: {
    txHash?: string;
    facilitatorReceipt?: string;
    /** For demo: allow mock payments */
    mock?: {
      amountUSDC: number;
      payer: string;
    };
  };
  /** User's Pedersen commitment (hides nullifier_seed) */
  userCommitment: {
    x: string;
    y: string;
  };
}

/** Response containing signed credential */
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

/** Verified payment result */
export interface PaymentResult {
  valid: boolean;
  amountUSDC: number;
  payer: string;
  txHash?: string;
}
