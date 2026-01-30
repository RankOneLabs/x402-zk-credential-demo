import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PaymentVerifier } from '../src/payment-verifier.js';

// ERC-20 Transfer event topic
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

// Test addresses (padded to 32 bytes for topics)
const SENDER_ADDRESS = '0x1234567890123456789012345678901234567890';
const RECIPIENT_ADDRESS = '0xaabbccddaabbccddaabbccddaabbccddaabbccdd';
const OTHER_ADDRESS = '0x9999999999999999999999999999999999999999';
const USDC_ADDRESS = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';

// Pad address to 32-byte topic
function addressToTopic(addr: string): `0x${string}` {
  return `0x000000000000000000000000${addr.slice(2).toLowerCase()}` as `0x${string}`;
}

// Encode uint256 value as log data
function encodeUint256(value: bigint): `0x${string}` {
  return `0x${value.toString(16).padStart(64, '0')}` as `0x${string}`;
}

describe('PaymentVerifier', () => {
  let mockClient: {
    getTransactionReceipt: ReturnType<typeof vi.fn>;
    waitForTransactionReceipt: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    mockClient = {
      getTransactionReceipt: vi.fn(),
      waitForTransactionReceipt: vi.fn(),
    };
  });

  function createVerifier(recipientAddress = RECIPIENT_ADDRESS): PaymentVerifier {
    const verifier = new PaymentVerifier({
      chainId: 84532,
      recipientAddress: recipientAddress as `0x${string}`,
    });
    // Inject mock client
    (verifier as unknown as { client: typeof mockClient }).client = mockClient;
    return verifier;
  }

  describe('findTransferToRecipient (via verifyTransaction)', () => {
    it('should find valid USDC transfer to recipient', async () => {
      const txHash = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
      const amount = 1_000_000n; // 1 USDC (6 decimals)

      mockClient.getTransactionReceipt.mockResolvedValue({
        status: 'success',
        from: SENDER_ADDRESS,
        blockNumber: 12345n,
        logs: [
          {
            address: USDC_ADDRESS,
            topics: [
              TRANSFER_TOPIC,
              addressToTopic(SENDER_ADDRESS),
              addressToTopic(RECIPIENT_ADDRESS),
            ],
            data: encodeUint256(amount),
          },
        ],
      });

      const verifier = createVerifier();
      const result = await verifier.verifyTransaction(txHash as `0x${string}`);

      expect(result.valid).toBe(true);
      expect(result.amountUSDC).toBe(1.0);
      expect(result.from.toLowerCase()).toBe(SENDER_ADDRESS.toLowerCase());
      expect(result.to.toLowerCase()).toBe(RECIPIENT_ADDRESS.toLowerCase());
      expect(result.blockNumber).toBe(12345n);
    });

    it('should reject transfer to wrong recipient', async () => {
      const txHash = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

      mockClient.getTransactionReceipt.mockResolvedValue({
        status: 'success',
        from: SENDER_ADDRESS,
        blockNumber: 12345n,
        logs: [
          {
            address: USDC_ADDRESS,
            topics: [
              TRANSFER_TOPIC,
              addressToTopic(SENDER_ADDRESS),
              addressToTopic(OTHER_ADDRESS), // Wrong recipient
            ],
            data: encodeUint256(1_000_000n),
          },
        ],
      });

      const verifier = createVerifier();
      const result = await verifier.verifyTransaction(txHash as `0x${string}`);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('No USDC transfer');
    });

    it('should ignore non-USDC contract transfers', async () => {
      const txHash = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

      mockClient.getTransactionReceipt.mockResolvedValue({
        status: 'success',
        from: SENDER_ADDRESS,
        blockNumber: 12345n,
        logs: [
          {
            address: OTHER_ADDRESS, // Not USDC contract
            topics: [
              TRANSFER_TOPIC,
              addressToTopic(SENDER_ADDRESS),
              addressToTopic(RECIPIENT_ADDRESS),
            ],
            data: encodeUint256(1_000_000n),
          },
        ],
      });

      const verifier = createVerifier();
      const result = await verifier.verifyTransaction(txHash as `0x${string}`);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('No USDC transfer');
    });

    it('should ignore non-Transfer events', async () => {
      const txHash = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
      const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';

      mockClient.getTransactionReceipt.mockResolvedValue({
        status: 'success',
        from: SENDER_ADDRESS,
        blockNumber: 12345n,
        logs: [
          {
            address: USDC_ADDRESS,
            topics: [
              APPROVAL_TOPIC, // Approval, not Transfer
              addressToTopic(SENDER_ADDRESS),
              addressToTopic(RECIPIENT_ADDRESS),
            ],
            data: encodeUint256(1_000_000n),
          },
        ],
      });

      const verifier = createVerifier();
      const result = await verifier.verifyTransaction(txHash as `0x${string}`);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('No USDC transfer');
    });
  });

  describe('amount decoding', () => {
    it('should correctly decode USDC amounts (6 decimals)', async () => {
      const txHash = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

      // Test various amounts
      const testCases = [
        { raw: 1_000_000n, expected: 1.0 },      // 1 USDC
        { raw: 10_000_000n, expected: 10.0 },    // 10 USDC
        { raw: 500_000n, expected: 0.5 },        // 0.5 USDC
        { raw: 1_234_567n, expected: 1.234567 }, // 1.234567 USDC
        { raw: 100n, expected: 0.0001 },         // 0.01 cents
      ];

      for (const { raw, expected } of testCases) {
        mockClient.getTransactionReceipt.mockResolvedValue({
          status: 'success',
          from: SENDER_ADDRESS,
          blockNumber: 12345n,
          logs: [
            {
              address: USDC_ADDRESS,
              topics: [
                TRANSFER_TOPIC,
                addressToTopic(SENDER_ADDRESS),
                addressToTopic(RECIPIENT_ADDRESS),
              ],
              data: encodeUint256(raw),
            },
          ],
        });

        const verifier = createVerifier();
        const result = await verifier.verifyTransaction(txHash as `0x${string}`);

        expect(result.valid).toBe(true);
        expect(result.amountUSDC).toBeCloseTo(expected, 6);
      }
    });
  });

  describe('transaction status handling', () => {
    it('should reject failed transactions', async () => {
      const txHash = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

      mockClient.getTransactionReceipt.mockResolvedValue({
        status: 'reverted',
        from: SENDER_ADDRESS,
        blockNumber: 12345n,
        logs: [],
      });

      const verifier = createVerifier();
      const result = await verifier.verifyTransaction(txHash as `0x${string}`);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Transaction failed');
    });

    it('should handle RPC errors gracefully', async () => {
      const txHash = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

      mockClient.getTransactionReceipt.mockRejectedValue(new Error('RPC timeout'));

      const verifier = createVerifier();
      const result = await verifier.verifyTransaction(txHash as `0x${string}`);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('RPC timeout');
    });
  });

  describe('recipient matching', () => {
    it('should match recipient case-insensitively', async () => {
      const txHash = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
      const mixedCaseRecipient = '0xAAbbCCddAAbbCCddAAbbCCddAAbbCCddAAbbCCdd';

      mockClient.getTransactionReceipt.mockResolvedValue({
        status: 'success',
        from: SENDER_ADDRESS,
        blockNumber: 12345n,
        logs: [
          {
            address: USDC_ADDRESS,
            topics: [
              TRANSFER_TOPIC,
              addressToTopic(SENDER_ADDRESS),
              addressToTopic(RECIPIENT_ADDRESS.toLowerCase()), // lowercase in log
            ],
            data: encodeUint256(1_000_000n),
          },
        ],
      });

      // Create verifier with mixed-case recipient
      const verifier = createVerifier(mixedCaseRecipient);
      const result = await verifier.verifyTransaction(txHash as `0x${string}`);

      expect(result.valid).toBe(true);
    });

    it('should find correct transfer when multiple logs present', async () => {
      const txHash = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

      mockClient.getTransactionReceipt.mockResolvedValue({
        status: 'success',
        from: SENDER_ADDRESS,
        blockNumber: 12345n,
        logs: [
          // First: wrong token contract
          {
            address: OTHER_ADDRESS,
            topics: [
              TRANSFER_TOPIC,
              addressToTopic(SENDER_ADDRESS),
              addressToTopic(RECIPIENT_ADDRESS),
            ],
            data: encodeUint256(999_000_000n),
          },
          // Second: wrong recipient
          {
            address: USDC_ADDRESS,
            topics: [
              TRANSFER_TOPIC,
              addressToTopic(SENDER_ADDRESS),
              addressToTopic(OTHER_ADDRESS),
            ],
            data: encodeUint256(888_000_000n),
          },
          // Third: correct USDC transfer to recipient
          {
            address: USDC_ADDRESS,
            topics: [
              TRANSFER_TOPIC,
              addressToTopic(SENDER_ADDRESS),
              addressToTopic(RECIPIENT_ADDRESS),
            ],
            data: encodeUint256(5_000_000n), // 5 USDC
          },
        ],
      });

      const verifier = createVerifier();
      const result = await verifier.verifyTransaction(txHash as `0x${string}`);

      expect(result.valid).toBe(true);
      expect(result.amountUSDC).toBe(5.0); // Correct amount from matching log
    });
  });

  describe('configuration', () => {
    it('should throw for unsupported chain ID', () => {
      expect(() => {
        new PaymentVerifier({
          chainId: 999999,
          recipientAddress: RECIPIENT_ADDRESS as `0x${string}`,
        });
      }).toThrow(/No USDC address configured for chain 999999|Chain ID 999999 is not a known chain/);
    });

    it('should expose chain ID and USDC address', () => {
      const verifier = new PaymentVerifier({
        chainId: 84532,
        recipientAddress: RECIPIENT_ADDRESS as `0x${string}`,
      });

      expect(verifier.getChainId()).toBe(84532);
      expect(verifier.getUsdcAddress().toLowerCase()).toBe(USDC_ADDRESS.toLowerCase());
    });
  });
});
