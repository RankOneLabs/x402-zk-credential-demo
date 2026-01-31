/**
 * Credential Issuer
 * 
 * Issues signed ZK session credentials after verifying x402 payment.
 */

import {
  schnorrSign,
  derivePublicKey,
  poseidonHash7,
  bigIntToHex,
  hexToBigInt,
  type Point,
} from '@demo/crypto';
import type { IssuanceRequest, IssuanceResponse, PaymentResult } from './types.js';
import { PaymentVerifier, type PaymentVerificationConfig } from './payment-verifier.js';

/** Configuration for a single tier */
export interface TierConfig {
  /** Minimum payment amount in USDC cents (e.g., 10 = $0.10) */
  minAmountCents: number;
  /** Tier level (0 = basic, 1 = pro, etc.) */
  tier: number;
  /** Maximum presentations allowed */
  maxPresentations: number;
  /** Duration in seconds */
  durationSeconds: number;
}

/** Issuer configuration */
export interface IssuerConfig {
  /** Unique service identifier */
  serviceId: bigint;
  /** Issuer's secret key for signing */
  secretKey: bigint;
  /** Pricing tiers (sorted by minAmountCents descending by the issuer) */
  tiers: TierConfig[];
  /** Enable mock payments for testing */
  allowMockPayments?: boolean;
  /** On-chain payment verification config */
  paymentVerification?: PaymentVerificationConfig;
}

export class CredentialIssuer {
  private publicKey: Point | null = null;
  private initializationPromise: Promise<void> | null = null;
  private readonly tiers: TierConfig[];
  private readonly paymentVerifier?: PaymentVerifier;

  constructor(private readonly config: IssuerConfig) {
    this.tiers = [...config.tiers].sort((a, b) => b.minAmountCents - a.minAmountCents);

    // Initialize payment verifier if configured
    if (config.paymentVerification) {
      this.paymentVerifier = new PaymentVerifier(config.paymentVerification);
      console.log(`[Issuer] On-chain verification enabled for chain ${config.paymentVerification.chainId}`);
    }
  }

  /**
   * Initialize the issuer (derive public key)
   */
  async initialize(): Promise<void> {
    // Return existing promise if initialization is in progress
    if (this.initializationPromise) {
      return this.initializationPromise;
    }

    if (!this.publicKey) {
      this.initializationPromise = (async () => {
        try {
          this.publicKey = await derivePublicKey(this.config.secretKey);
        } finally {
          // Clear promise on error, but keep it if successful so we don't re-run.
          // Actually, if we succeed, this.publicKey is set, so subsequent calls check that.
          // But to be completely safe against re-entrancy even after success:
          // We can just leave the promise or use the double-check locking pattern properly.
          // However, simpler is just to await the promise.
        }
      })();

      await this.initializationPromise;
    }
  }

  /**
   * Get the issuer's public key
   */
  async getPublicKey(): Promise<Point> {
    if (!this.publicKey) {
      await this.initialize();
    }
    return this.publicKey!;
  }

  /**
   * Issue a credential after verifying payment
   */
  async issueCredential(request: IssuanceRequest): Promise<IssuanceResponse> {
    // Ensure initialized (public key derived) to prevent race conditions
    await this.initialize();

    // 1. Verify payment
    const payment = await this.verifyPayment(request.paymentProof);
    if (!payment.valid) {
      throw new Error('Invalid payment proof');
    }

    // 2. Determine tier from payment amount
    // Convert to integer cents to avoid floating-point precision issues
    const amountCents = Math.round(payment.amountUSDC * 100);
    const tierConfig = this.tiers.find(t => amountCents >= t.minAmountCents);
    if (!tierConfig) {
      throw new Error(`Payment amount $${payment.amountUSDC} below minimum tier`);
    }

    // 3. Build credential
    const now = Math.floor(Date.now() / 1000);
    const userCommitment: Point = {
      x: hexToBigInt(request.userCommitment.x),
      y: hexToBigInt(request.userCommitment.y),
    };

    // 4. Compute message hash for signature
    const message = poseidonHash7(
      this.config.serviceId,
      BigInt(tierConfig.tier),
      BigInt(tierConfig.maxPresentations),
      BigInt(now),
      BigInt(now + tierConfig.durationSeconds),
      userCommitment.x,
      userCommitment.y,
    );

    // 5. Sign with Schnorr
    const signature = await schnorrSign(this.config.secretKey, message);

    const pubKey = await this.getPublicKey();

    // 6. Return signed credential
    return {
      credential: {
        serviceId: bigIntToHex(this.config.serviceId),
        tier: tierConfig.tier,
        maxPresentations: tierConfig.maxPresentations,
        issuedAt: now,
        expiresAt: now + tierConfig.durationSeconds,
        userCommitment: {
          x: bigIntToHex(userCommitment.x),
          y: bigIntToHex(userCommitment.y),
        },
        signature: {
          r: {
            x: bigIntToHex(signature.r.x),
            y: bigIntToHex(signature.r.y),
          },
          s: bigIntToHex(signature.s),
        },
        issuerPubkey: {
          x: bigIntToHex(pubKey.x),
          y: bigIntToHex(pubKey.y),
        },
      },
    };
  }

  /**
   * Verify an x402 payment
   */
  private async verifyPayment(
    proof: IssuanceRequest['paymentProof']
  ): Promise<PaymentResult> {
    // Mock payments for development/testing
    if (proof.mock && this.config.allowMockPayments) {
      console.log(`[Issuer] Accepting mock payment: $${proof.mock.amountUSDC} from ${proof.mock.payer}`);
      return {
        valid: true,
        amountUSDC: proof.mock.amountUSDC,
        payer: proof.mock.payer,
      };
    }

    // On-chain payment verification
    if (proof.txHash) {
      if (!this.paymentVerifier) {
        console.error(`[Issuer] On-chain verification requested but not configured`);
        return { valid: false, amountUSDC: 0, payer: '' };
      }

      const txHash = proof.txHash;
      if (typeof txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
        console.error(`[Issuer] Invalid txHash format for on-chain verification: ${txHash}`);
        return { valid: false, amountUSDC: 0, payer: '' };
      }

      const result = await this.paymentVerifier.verifyTransaction(txHash as `0x${string}`);

      if (!result.valid) {
        console.error(`[Issuer] Payment verification failed: ${result.error}`);
        return { valid: false, amountUSDC: 0, payer: '' };
      }

      return {
        valid: true,
        amountUSDC: result.amountUSDC,
        payer: result.from,
        txHash: result.txHash,
      };
    }

    if (proof.facilitatorReceipt) {
      // TODO: Verify with x402 facilitator API
      console.log(`[Issuer] Facilitator verification not yet implemented`);
      return { valid: false, amountUSDC: 0, payer: '' };
    }

    return { valid: false, amountUSDC: 0, payer: '' };
  }
}
