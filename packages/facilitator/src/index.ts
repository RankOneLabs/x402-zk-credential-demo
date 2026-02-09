/**
 * @demo/facilitator
 * 
 * Credential facilitator server for ZK Credential (x402 spec v0.1.0).
 * Issues signed credentials after x402 payment verification.
 */

export { CredentialIssuer, type IssuerConfig, type TierConfig } from './issuer.js';
export { 
  createFacilitatorServer, 
  type FacilitatorServerConfig,
} from './server.js';
export { PaymentVerifier, type PaymentVerificationConfig, type VerifiedPayment } from './payment-verifier.js';
export type { 
  SettlementRequest, 
  SettlementResponse, 
  PaymentResult,
} from './types.js';
