/**
 * Credential Facilitator
 * 
 * Issues signed ZK credentials after verifying and settling x402 payment.
 * Compliant with x402 zk-credential spec v0.1.0
 */

import {
  schnorrSign,
  derivePublicKey,
  poseidonHash6,
  bigIntToHex,
  hexToBigInt,
  parseSchemePrefix,
  addSchemePrefix,
  type Point,
  type PaymentPayload,
  type PaymentRequirements,
  toBase64Url,
  fromBase64Url,
  pointToBytes,
  bytesToPoint,
  fieldToBytes,
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
  /** Maximum identities/presentations allowed (identityLimit per spec) */
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
  /** Key ID for the secret key (optional, defaults to '1') */
  kid?: string;
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
    const pubKeyBytes = pointToBytes(pubKey);
    const pubKeyB64 = toBase64Url(pubKeyBytes);
    return addSchemePrefix('pedersen-schnorr-poseidon-ultrahonk', pubKeyB64);
  }

  /**
   * Settle payment and issue credential (spec §8.3, §8.4)
   */
  async settle(request: SettlementRequest): Promise<SettlementResponse> {
    await this.initialize();

    const { scheme, value: commitmentB64 } = parseSchemePrefix(request.extensions['zk-credential'].commitment);
    if (scheme !== 'pedersen-schnorr-poseidon-ultrahonk') {
      throw new Error(`Unsupported suite: ${scheme}`);
    }

    const commitmentBytes = fromBase64Url(commitmentB64);

    let userCommitment: Point;
    try {
      userCommitment = bytesToPoint(commitmentBytes);
    } catch {
      throw new Error('Invalid commitment format: expected 65 bytes starting with 0x04');
    }

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

    const message = poseidonHash6(
      this.config.serviceId,
      BigInt(tierConfig.tier),
      BigInt(tierConfig.identityLimit),
      BigInt(expiresAt),
      userCommitment.x,
      userCommitment.y,
    );

    const signature = await schnorrSign(this.config.secretKey, message);

    // Signature (r.x + r.y + s) -> 96 bytes -> base64url
    const sigBytes = new Uint8Array(96);
    sigBytes.set(fieldToBytes(signature.r.x), 0);
    sigBytes.set(fieldToBytes(signature.r.y), 32);
    sigBytes.set(fieldToBytes(signature.s), 64);
    const sigB64 = toBase64Url(sigBytes);

    const commitmentOutBytes = pointToBytes(userCommitment);
    const commitmentOutB64 = toBase64Url(commitmentOutBytes);
    const commitmentOutPrefixed = addSchemePrefix(
      'pedersen-schnorr-poseidon-ultrahonk',
      commitmentOutB64
    );

    const response: SettlementResponse = {
      payment_receipt: {
        status: 'settled',
        txHash: settleResult.transaction,
        amountUSDC,
      },
      extensions: {
        'zk-credential': {
          credential: {
            suite: 'pedersen-schnorr-poseidon-ultrahonk',
            service_id: toBase64Url(fieldToBytes(this.config.serviceId)),
            tier: tierConfig.tier,
            identity_limit: tierConfig.identityLimit,
            kid: this.config.kid ?? '1',
            expires_at: expiresAt,
            commitment: commitmentOutPrefixed,
            signature: sigB64,
          },
        },
      },
    };

    console.log('[Facilitator] Issued credential for tier', tierConfig.tier);
    return response;
  }

}
