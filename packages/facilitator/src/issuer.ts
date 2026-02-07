/**
 * Credential Facilitator
 * 
 * Issues signed ZK credentials after verifying and settling x402 payment.
 * Compliant with x402 zk-credential spec v0.2.0
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
  type PaymentPayload,
  type PaymentRequirements,
} from '@demo/crypto';
import type { SettlementRequest, SettlementResponse } from './types.js';
// Import from exact/facilitator for server-side verify/settle
import { ExactEvmScheme } from '@x402/evm/exact/facilitator';
import type { FacilitatorEvmSigner } from '@x402/evm';
import {
  http,
  createPublicClient,
  createWalletClient,
  verifyTypedData,
  defineChain,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { baseSepolia } from 'viem/chains';

// Local Anvil chain definition
const anvil = defineChain({
  id: 31337,
  name: 'Anvil',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: {
    default: { http: ['http://127.0.0.1:8545'] },
  },
  testnet: true,
});

/**
 * Get the appropriate chain configuration based on chainId
 */
function getChain(chainId: number, rpcUrl: string) {
  if (chainId === 84532) {
    return baseSepolia;
  } else if (chainId === 31337) {
    return anvil;
  } else {
    // Create a custom chain definition for unknown chains
    return defineChain({
      id: chainId,
      name: `Chain ${chainId}`,
      nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
      rpcUrls: {
        default: { http: [rpcUrl] },
      },
    });
  }
}

/** Configuration for a single tier */
export interface TierConfig {
  /** Minimum payment amount in USDC cents (e.g., 10 = $0.10) */
  minAmountCents: number;
  /** Tier level (0 = basic, 1 = pro, etc.) */
  tier: number;
  /** Maximum presentations allowed (presentation_budget per spec) */
  identityLimit: number;
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
    const chain = getChain(evmConfig.chainId, evmConfig.rpcUrl);
    const transport = http(evmConfig.rpcUrl);

    const publicClient = createPublicClient({ chain, transport });
    const walletClient = createWalletClient({ account, chain, transport });

    // Create a FacilitatorEvmSigner compatible with @x402/evm/exact/facilitator
    const signer: FacilitatorEvmSigner = {
      getAddresses: () => [account.address] as readonly `0x${string}`[],
      readContract: (args) => publicClient.readContract(args as any),
      verifyTypedData: (args) => verifyTypedData(args as any),
      writeContract: (args) => walletClient.writeContract(args as any),
      sendTransaction: (args) => walletClient.sendTransaction({
        to: args.to,
        data: args.data,
        account,
        chain: null,
      }),
      waitForTransactionReceipt: (args) => publicClient.waitForTransactionReceipt(args) as any,
      getCode: (args) => publicClient.getCode(args),
    };

    this.evmScheme = new ExactEvmScheme(signer);
    console.log(`[Facilitator] EVM payment scheme initialized for chain ${evmConfig.chainId}`);
  }

  /**
   * Initialize the facilitator (derive public key)
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
   * Get the facilitator's public key
   */
  async getPublicKey(): Promise<Point> {
    if (!this.publicKey) {
      await this.initialize();
    }
    return this.publicKey!;
  }

  /**
   * Get the suite-prefixed public key string for x402 responses
   */
  async getPublicKeyPrefixed(): Promise<string> {
    const pubKey = await this.getPublicKey();
    const xHex = pubKey.x.toString(16).padStart(64, '0');
    const yHex = pubKey.y.toString(16).padStart(64, '0');
    return addSchemePrefix('pedersen-schnorr-poseidon-ultrahonk', `0x04${xHex}${yHex}`);
  }

  /**
   * Settle payment and issue credential (spec §8.3, §8.4)
   */
  async settle(request: SettlementRequest): Promise<SettlementResponse> {
    await this.initialize();

    const { scheme, value: commitmentHex } = parseSchemePrefix(request.extensions.zk_credential.commitment);
    if (scheme !== 'pedersen-schnorr-poseidon-ultrahonk') {
      throw new Error(`Unsupported suite: ${scheme}`);
    }

    const commitmentBytes = commitmentHex.startsWith('0x') ? commitmentHex.slice(2) : commitmentHex;
    if (!commitmentBytes.startsWith('04') || commitmentBytes.length !== 130) {
      throw new Error('Invalid commitment format: expected uncompressed point (04 + 64 hex x + 64 hex y)');
    }
    const userCommitment: Point = {
      x: hexToBigInt('0x' + commitmentBytes.slice(2, 66)),
      y: hexToBigInt('0x' + commitmentBytes.slice(66, 130)),
    };

    if (!this.evmScheme) {
      throw new Error('EVM payment scheme not configured');
    }

    const verifyResult = await this.evmScheme.verify(request.payment, request.paymentRequirements);
    if (!verifyResult.isValid) {
      throw new Error(`Payment verification failed: ${verifyResult.invalidReason}`);
    }

    const settleResult = await this.evmScheme.settle(request.payment, request.paymentRequirements);
    if (!settleResult.success) {
      throw new Error(`Payment settlement failed: ${settleResult.errorReason}`);
    }

    console.log(`[Facilitator] Payment settled: ${settleResult.transaction}`);

    const usdcDecimals = this.config.evmPayment?.usdcDecimals ?? 6;
    const amountUSDC = Number(BigInt(request.paymentRequirements.amount)) / Math.pow(10, usdcDecimals);
    const amountCents = Math.round(amountUSDC * 100);
    const tierConfig = this.tiers.find(t => amountCents >= t.minAmountCents);
    if (!tierConfig) {
      throw new Error(`Payment amount $${amountUSDC} below minimum tier`);
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + tierConfig.durationSeconds;

    const message = poseidonHash7(
      this.config.serviceId,
      BigInt(tierConfig.tier),
      BigInt(tierConfig.identityLimit),
      BigInt(now),
      BigInt(expiresAt),
      userCommitment.x,
      userCommitment.y,
    );

    const signature = await schnorrSign(this.config.secretKey, message);

    const sigHex = '0x' +
      signature.r.x.toString(16).padStart(64, '0') +
      signature.r.y.toString(16).padStart(64, '0') +
      signature.s.toString(16).padStart(64, '0');

    const commitmentOutHex = addSchemePrefix(
      'pedersen-schnorr-poseidon-ultrahonk',
      '0x04' +
      userCommitment.x.toString(16).padStart(64, '0') +
      userCommitment.y.toString(16).padStart(64, '0')
    );

    const response: SettlementResponse = {
      payment_receipt: {
        status: 'settled',
        txHash: settleResult.transaction,
        amountUSDC,
      },
      extensions: {
        zk_credential: {
          credential: {
            suite: 'pedersen-schnorr-poseidon-ultrahonk',
            service_id: bigIntToHex(this.config.serviceId),
            tier: tierConfig.tier,
            identity_limit: tierConfig.identityLimit,
            issued_at: now,
            expires_at: expiresAt,
            commitment: commitmentOutHex,
            signature: sigHex,
          },
        },
      },
    };

    console.log('[Facilitator] Issued credential for tier', tierConfig.tier);
    return response;
  }

}
