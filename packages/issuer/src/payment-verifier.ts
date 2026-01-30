/**
 * On-Chain Payment Verification
 * 
 * Verifies USDC transfers on Base Sepolia (or local Anvil) for x402 payments.
 */

import {
  createPublicClient,
  http,
  type Hash,
  type Log,
  defineChain,
} from 'viem';
import { baseSepolia } from 'viem/chains';

// USDC contract addresses
const USDC_ADDRESSES: Record<number, `0x${string}`> = {
  // Base Sepolia testnet USDC
  84532: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
  // Local Anvil (forked from Base Sepolia)
  31337: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
};

// Define local Anvil chain (typically forked from Base Sepolia)
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
function getChain(chainId: number, rpcUrl?: string) {
  if (chainId === 84532) {
    return baseSepolia;
  } else if (chainId === 31337) {
    return anvil;
  } else {
    // For unknown chains, require an RPC URL
    if (!rpcUrl) {
      throw new Error(
        `Chain ID ${chainId} is not a known chain. Please provide an rpcUrl in the config.`
      );
    }
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

export interface PaymentVerificationConfig {
  /** Chain ID (84532 for Base Sepolia, 31337 for local Anvil) */
  chainId: number;
  /** RPC URL (optional, uses default for known chains) */
  rpcUrl?: string;
  /** Expected recipient address (your service's payment address) */
  recipientAddress: `0x${string}`;
  /** USDC decimals (6 for standard USDC) */
  usdcDecimals?: number;
}

export interface VerifiedPayment {
  valid: boolean;
  txHash: string;
  from: string;
  to: string;
  amountUSDC: number;
  blockNumber: bigint;
  error?: string;
}

export class PaymentVerifier {
  // Use 'any' to avoid viem's complex generic chain types
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private client: any;
  private usdcAddress: `0x${string}`;
  private usdcDecimals: number;
  
  constructor(private readonly config: PaymentVerificationConfig) {
    // Get the appropriate chain definition based on chainId
    const chain = getChain(config.chainId, config.rpcUrl);
    
    // Create viem client with the correct chain
    // Use provided RPC URL or fall back to chain's default
    this.client = createPublicClient({
      chain,
      transport: http(config.rpcUrl ?? chain.rpcUrls.default.http[0]),
    });
    
    // Get USDC address for this chain
    this.usdcAddress = USDC_ADDRESSES[config.chainId];
    if (!this.usdcAddress) {
      throw new Error(`No USDC address configured for chain ${config.chainId}`);
    }
    
    this.usdcDecimals = config.usdcDecimals ?? 6;
  }
  
  /**
   * Verify a payment transaction on-chain
   * 
   * @param txHash - Transaction hash to verify
   * @returns Verified payment details
   */
  async verifyTransaction(txHash: Hash): Promise<VerifiedPayment> {
    try {
      console.log(`[PaymentVerifier] Verifying tx: ${txHash}`);
      
      // 1. Get transaction receipt
      const receipt = await this.client.getTransactionReceipt({ hash: txHash });
      
      if (receipt.status !== 'success') {
        return {
          valid: false,
          txHash,
          from: '',
          to: '',
          amountUSDC: 0,
          blockNumber: 0n,
          error: 'Transaction failed',
        };
      }
      
      // 2. Find USDC Transfer event to our recipient
      const transferLog = this.findTransferToRecipient(receipt.logs);
      
      if (!transferLog) {
        return {
          valid: false,
          txHash,
          from: receipt.from,
          to: '',
          amountUSDC: 0,
          blockNumber: receipt.blockNumber,
          error: `No USDC transfer to ${this.config.recipientAddress} found`,
        };
      }
      
      // 3. Decode transfer amount
      const amountRaw = transferLog.args.value as bigint;
      const amountUSDC = Number(amountRaw) / Math.pow(10, this.usdcDecimals);
      
      console.log(`[PaymentVerifier] Verified: $${amountUSDC} USDC from ${transferLog.args.from}`);
      
      return {
        valid: true,
        txHash,
        from: transferLog.args.from as string,
        to: transferLog.args.to as string,
        amountUSDC,
        blockNumber: receipt.blockNumber,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[PaymentVerifier] Error verifying tx ${txHash}:`, message);
      
      return {
        valid: false,
        txHash,
        from: '',
        to: '',
        amountUSDC: 0,
        blockNumber: 0n,
        error: message,
      };
    }
  }
  
  /**
   * Wait for a transaction to be confirmed and verify it
   * 
   * @param txHash - Transaction hash
   * @param confirmations - Number of confirmations to wait for (default: 1)
   */
  async waitAndVerify(txHash: Hash, confirmations = 1): Promise<VerifiedPayment> {
    console.log(`[PaymentVerifier] Waiting for ${confirmations} confirmation(s)...`);
    
    // Wait for transaction to be mined
    await this.client.waitForTransactionReceipt({
      hash: txHash,
      confirmations,
    });
    
    return this.verifyTransaction(txHash);
  }
  
  /**
   * Find Transfer event to our recipient address
   */
  private findTransferToRecipient(logs: Log[]): {
    args: { from: string; to: string; value: bigint };
  } | undefined {
    for (const log of logs) {
      // Check if this is from the USDC contract
      if (log.address.toLowerCase() !== this.usdcAddress.toLowerCase()) {
        continue;
      }
      
      // Check if this is a Transfer event (topic[0] matches)
      const transferTopic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
      if (log.topics[0] !== transferTopic) {
        continue;
      }
      
      // Decode the event
      // topics[1] = from (indexed), topics[2] = to (indexed), data = value
      const from = '0x' + log.topics[1]!.slice(26);
      const to = '0x' + log.topics[2]!.slice(26);
      const value = BigInt(log.data);
      
      // Check if recipient matches
      if (to.toLowerCase() === this.config.recipientAddress.toLowerCase()) {
        return { args: { from, to, value } };
      }
    }
    
    return undefined;
  }
  
  /**
   * Get the configured chain ID
   */
  getChainId(): number {
    return this.config.chainId;
  }
  
  /**
   * Get the USDC contract address
   */
  getUsdcAddress(): string {
    return this.usdcAddress;
  }
}
