/**
 * Credential Facilitator
 * 
 * Issues signed ZK session credentials after verifying and settling x402 payment.
 * Compliant with x402 zk-session spec v0.1.0
 */

import {
  schnorrSign,
  derivePublicKey,
  poseidonHash7,
  bigIntToHex,
  hexToBigInt,
  parseSchemePrefix,
  addSchemePrefix,
  type Point,
  type ZKSessionScheme,
  type PaymentPayload,
  type PaymentRequirements,
} from '@demo/crypto';
import type { SettlementRequest, SettlementResponse } from './types.js';
// Import from exact/facilitator for server-side verify/settle
import { ExactEvmScheme } from '@x402/evm/exact/facilitator';
import type { FacilitatorEvmSigner } from '@x402/evm';
import { http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

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

/** EVM chain configuration for payment settlement */
export interface EvmPaymentConfig {
  /** Chain ID (e.g., 31337 for Anvil, 84532 for Base Sepolia) */
  chainId: number;
  /** RPC URL for the chain */
  rpcUrl: string;
  /** Facilitator's private key for executing transfers */
  facilitatorPrivateKey: `0x${string}`;
  /** USDC contract address */
  usdcAddress: `0x${string}`;
  /** USDC decimals (typically 6) */
  usdcDecimals?: number;
}

/** Issuer configuration */
export interface IssuerConfig {
  /** Unique service identifier */
  serviceId: bigint;
  /** Issuer's secret key for signing ZK credentials */
  secretKey: bigint;
  /** Pricing tiers (sorted by minAmountCents descending by the issuer) */
  tiers: TierConfig[];
  /** Enable mock payments for testing */
  allowMockPayments?: boolean;
  /** EVM payment configuration for executing transfers */
  evmPayment?: EvmPaymentConfig;
}

export class CredentialIssuer {
  private publicKey: Point | null = null;
  private initializationPromise: Promise<void> | null = null;
  private readonly tiers: TierConfig[];
  private evmScheme?: ExactEvmScheme;

  constructor(private readonly config: IssuerConfig) {
    this.tiers = [...config.tiers].sort((a, b) => b.minAmountCents - a.minAmountCents);

    // Initialize EVM payment scheme if configured
    if (config.evmPayment) {
      this.initializeEvmScheme(config.evmPayment);
    }
  }

  /**
   * Initialize the x402 EVM payment scheme
   */
  private initializeEvmScheme(evmConfig: EvmPaymentConfig): void {
    const account = privateKeyToAccount(evmConfig.facilitatorPrivateKey);
    
    // Create a FacilitatorEvmSigner compatible with @x402/evm/exact/facilitator
    const signer: FacilitatorEvmSigner = {
      // Get all addresses this facilitator can use (just one for now)
      getAddresses: () => [account.address] as readonly `0x${string}`[],
      
      // Read contract state
      readContract: async (args) => {
        const { createPublicClient } = await import('viem');
        const client = createPublicClient({
          transport: http(evmConfig.rpcUrl),
        });
        return client.readContract(args as any);
      },
      
      // Verify typed data signature (EIP-712)
      verifyTypedData: async (args) => {
        const { verifyTypedData } = await import('viem');
        return verifyTypedData(args as any);
      },
      
      // Write contract - executes transferWithAuthorization
      writeContract: async (args) => {
        const { createWalletClient } = await import('viem');
        const client = createWalletClient({
          account,
          transport: http(evmConfig.rpcUrl),
        });
        return client.writeContract(args as any);
      },
      
      // Send raw transaction
      sendTransaction: async (args) => {
        const { createWalletClient } = await import('viem');
        const client = createWalletClient({
          account,
          transport: http(evmConfig.rpcUrl),
        });
        return client.sendTransaction({
          to: args.to,
          data: args.data,
          account,
          chain: null,
        });
      },
      
      // Wait for transaction receipt
      waitForTransactionReceipt: async (args) => {
        const { createPublicClient } = await import('viem');
        const client = createPublicClient({
          transport: http(evmConfig.rpcUrl),
        });
        return client.waitForTransactionReceipt(args) as any;
      },
      
      // Get contract code
      getCode: async (args) => {
        const { createPublicClient } = await import('viem');
        const client = createPublicClient({
          transport: http(evmConfig.rpcUrl),
        });
        return client.getCode(args);
      },
    };
    
    this.evmScheme = new ExactEvmScheme(signer);
    console.log(`[Facilitator] EVM payment scheme initialized for chain ${evmConfig.chainId}`);
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
   * Get the scheme-prefixed public key string for x402 responses
   */
  async getPublicKeyPrefixed(): Promise<string> {
    const pubKey = await this.getPublicKey();
    // Encode as uncompressed point: 04 + x + y (each 32 bytes, 64 hex chars)
    const xHex = pubKey.x.toString(16).padStart(64, '0');
    const yHex = pubKey.y.toString(16).padStart(64, '0');
    return addSchemePrefix('pedersen-schnorr-bn254', `0x04${xHex}${yHex}`);
  }

  /**
   * Settle payment and issue credential (spec §7.2, §7.3)
   * Uses x402 v2 signed payload flow with EIP-3009 transferWithAuthorization
   */
  async settle(request: SettlementRequest): Promise<SettlementResponse> {
    await this.initialize();

    // 1. Parse scheme-prefixed commitment
    const { scheme, value: commitmentHex } = parseSchemePrefix(request.zk_session.commitment);
    if (scheme !== 'pedersen-schnorr-bn254') {
      throw new Error(`Unsupported scheme: ${scheme}`);
    }

    // Parse commitment point from hex (expects "0x04" + x (64 chars) + y (64 chars))
    const commitmentBytes = commitmentHex.startsWith('0x') ? commitmentHex.slice(2) : commitmentHex;
    if (!commitmentBytes.startsWith('04') || commitmentBytes.length !== 130) {
      throw new Error('Invalid commitment format: expected uncompressed point (04 + 64 hex x + 64 hex y)');
    }
    const userCommitment: Point = {
      x: hexToBigInt('0x' + commitmentBytes.slice(2, 66)),
      y: hexToBigInt('0x' + commitmentBytes.slice(66, 130)),
    };

    // 2. Verify and settle payment using x402 EVM scheme
    if (!this.evmScheme) {
      throw new Error('EVM payment scheme not configured');
    }

    // First verify the payment payload
    const verifyResult = await this.evmScheme.verify(request.payment, request.paymentRequirements);
    if (!verifyResult.isValid) {
      throw new Error(`Payment verification failed: ${verifyResult.invalidReason}`);
    }

    // Then settle (execute the transferWithAuthorization)
    const settleResult = await this.evmScheme.settle(request.payment, request.paymentRequirements);
    if (!settleResult.success) {
      throw new Error(`Payment settlement failed: ${settleResult.errorReason}`);
    }

    console.log(`[Facilitator] Payment settled: ${settleResult.transaction}`);

    // 3. Determine tier from payment amount
    const usdcDecimals = this.config.evmPayment?.usdcDecimals ?? 6;
    const amountUSDC = Number(BigInt(request.paymentRequirements.amount)) / Math.pow(10, usdcDecimals);
    const amountCents = Math.round(amountUSDC * 100);
    const tierConfig = this.tiers.find(t => amountCents >= t.minAmountCents);
    if (!tierConfig) {
      throw new Error(`Payment amount $${amountUSDC} below minimum tier`);
    }

    // 4. Build credential
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + tierConfig.durationSeconds;

    // 5. Compute message hash for signature (spec §9)
    const message = poseidonHash7(
      this.config.serviceId,
      BigInt(tierConfig.tier),
      BigInt(tierConfig.maxPresentations),
      BigInt(now),
      BigInt(expiresAt),
      userCommitment.x,
      userCommitment.y,
    );

    // 6. Sign with Schnorr
    const signature = await schnorrSign(this.config.secretKey, message);

    // 7. Encode signature as hex string
    const sigHex = '0x' +
      signature.r.x.toString(16).padStart(64, '0') +
      signature.r.y.toString(16).padStart(64, '0') +
      signature.s.toString(16).padStart(64, '0');

    // 8. Encode commitment as hex
    const commitmentOutHex = '0x04' +
      userCommitment.x.toString(16).padStart(64, '0') +
      userCommitment.y.toString(16).padStart(64, '0');

    // 9. Return settlement response (spec §7.3)
    const response: SettlementResponse = {
      payment_receipt: {
        status: 'settled',
        txHash: settleResult.transaction,
        amountUSDC,
      },
      zk_session: {
        credential: {
          scheme: 'pedersen-schnorr-bn254',
          service_id: bigIntToHex(this.config.serviceId),
          tier: tierConfig.tier,
          max_presentations: tierConfig.maxPresentations,
          issued_at: now,
          expires_at: expiresAt,
          commitment: commitmentOutHex,
          signature: sigHex,
        },
      },
    };

    console.log('[Facilitator] Issued credential for tier', tierConfig.tier);
    return response;
  }
}
