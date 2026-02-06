import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CredentialIssuer, type IssuerConfig, type TierConfig } from '../src/issuer.js';
import type { SettlementRequest } from '../src/types.js';
import type { PaymentPayload, PaymentRequirements, Point } from '@demo/crypto';

// Mock the crypto module for consistent test results
vi.mock('@demo/crypto', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    // Keep real implementations for parsing/encoding
    parseSchemePrefix: actual.parseSchemePrefix,
    addSchemePrefix: actual.addSchemePrefix,
    hexToBigInt: actual.hexToBigInt,
    bigIntToHex: actual.bigIntToHex,
    // Mock crypto operations for deterministic tests
    derivePublicKey: vi.fn().mockResolvedValue({
      x: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn,
      y: 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321n,
    }),
    schnorrSign: vi.fn().mockResolvedValue({
      r: {
        x: 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaan,
        y: 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbn,
      },
      s: 0xccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccn,
    }),
    poseidonHash7: vi.fn().mockReturnValue(0x123456789abcdef0n),
  };
});

// Test data
const TEST_SERVICE_ID = 1001n;
const TEST_SECRET_KEY = 123456789n;
const TEST_TIERS: TierConfig[] = [
  { minAmountCents: 100, tier: 2, presentationBudget: 50, durationSeconds: 86400 }, // $1.00
  { minAmountCents: 10, tier: 1, presentationBudget: 10, durationSeconds: 3600 },   // $0.10
];

const TEST_COMMITMENT_X = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
const TEST_COMMITMENT_Y = 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321';
const TEST_COMMITMENT = `pedersen-schnorr-poseidon-ultrahonk:0x04${TEST_COMMITMENT_X}${TEST_COMMITMENT_Y}`;

const TEST_PAYMENT_PAYLOAD: PaymentPayload = {
  x402Version: 2,
  resource: { url: 'https://example.com/api' },
  accepted: {
    scheme: 'exact',
    network: 'eip155:31337',
    asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
    amount: '100000', // $0.10 USDC (6 decimals)
    payTo: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    maxTimeoutSeconds: 300,
    extra: {},
  },
  payload: {
    authorization: {
      from: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      to: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      value: '100000',
      validAfter: '0',
      validBefore: '9999999999',
      nonce: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
    },
    signature: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
  },
};

const TEST_PAYMENT_REQUIREMENTS: PaymentRequirements = {
  scheme: 'exact',
  network: 'eip155:31337',
  asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
  amount: '100000',
  payTo: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
  maxTimeoutSeconds: 300,
  extra: { name: 'USD Coin', version: '1' },
};

describe('CredentialIssuer.settle()', () => {
  let mockEvmScheme: {
    verify: ReturnType<typeof vi.fn>;
    settle: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    mockEvmScheme = {
      verify: vi.fn().mockResolvedValue({ isValid: true }),
      settle: vi.fn().mockResolvedValue({
        success: true,
        transaction: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
        network: 'eip155:31337',
      }),
    };
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-15T12:00:00Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  function createIssuer(configOverrides: Partial<IssuerConfig> = {}): CredentialIssuer {
    const config: IssuerConfig = {
      serviceId: TEST_SERVICE_ID,
      secretKey: TEST_SECRET_KEY,
      tiers: TEST_TIERS,
      allowMockPayments: false,
      evmPayment: {
        chainId: 31337,
        rpcUrl: 'http://localhost:8545',
        facilitatorPrivateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
        usdcAddress: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
        usdcDecimals: 6,
      },
      ...configOverrides,
    };
    const issuer = new CredentialIssuer(config);
    // Inject mock EVM scheme
    (issuer as unknown as { evmScheme: typeof mockEvmScheme }).evmScheme = mockEvmScheme;
    return issuer;
  }

  function createSettlementRequest(overrides: Partial<SettlementRequest> = {}): SettlementRequest {
    return {
      payment: TEST_PAYMENT_PAYLOAD,
      paymentRequirements: TEST_PAYMENT_REQUIREMENTS,
      extensions: {
        zk_credential: {
          commitment: TEST_COMMITMENT,
        },
      },
      ...overrides,
    };
  }

  describe('successful settlement', () => {
    it('should settle valid EIP-3009 authorization and issue credential', async () => {
      const issuer = createIssuer();
      const request = createSettlementRequest();

      const response = await issuer.settle(request);

      // Verify payment was verified and settled
      expect(mockEvmScheme.verify).toHaveBeenCalledWith(
        TEST_PAYMENT_PAYLOAD,
        TEST_PAYMENT_REQUIREMENTS
      );
      expect(mockEvmScheme.settle).toHaveBeenCalledWith(
        TEST_PAYMENT_PAYLOAD,
        TEST_PAYMENT_REQUIREMENTS
      );

      // Verify response structure
      expect(response.payment_receipt.status).toBe('settled');
      expect(response.payment_receipt.txHash).toBe('0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab');
      expect(response.payment_receipt.amountUSDC).toBe(0.1); // 100000 / 10^6

      // Verify credential structure
      const cred = response.extensions.zk_credential.credential;
      expect(cred.suite).toBe('pedersen-schnorr-poseidon-ultrahonk');
      expect(cred.service_id).toBe('0x00000000000000000000000000000000000000000000000000000000000003e9'); // 1001n
      expect(cred.tier).toBe(1); // $0.10 qualifies for tier 1
      expect(cred.presentation_budget).toBe(10);
      expect(cred.issued_at).toBe(Math.floor(new Date('2026-01-15T12:00:00Z').getTime() / 1000));
      expect(cred.expires_at).toBe(cred.issued_at + 3600); // tier 1 duration
      expect(cred.commitment).toMatch(/^pedersen-schnorr-poseidon-ultrahonk:0x04[a-f0-9]{128}$/);
      expect(cred.signature).toMatch(/^0x[a-f0-9]{192}$/); // r.x + r.y + s
    });

    it('should assign higher tier for larger payment', async () => {
      const issuer = createIssuer();
      const request = createSettlementRequest({
        paymentRequirements: {
          ...TEST_PAYMENT_REQUIREMENTS,
          amount: '1000000', // $1.00 USDC
        },
      });

      const response = await issuer.settle(request);

      expect(response.extensions.zk_credential.credential.tier).toBe(2); // $1.00 qualifies for tier 2
      expect(response.extensions.zk_credential.credential.presentation_budget).toBe(50);
      expect(response.extensions.zk_credential.credential.expires_at).toBe(
        response.extensions.zk_credential.credential.issued_at + 86400 // tier 2 duration
      );
    });

    it('should correctly compute amountUSDC with different decimals', async () => {
      const issuer = createIssuer({
        evmPayment: {
          chainId: 31337,
          rpcUrl: 'http://localhost:8545',
          facilitatorPrivateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
          usdcAddress: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
          usdcDecimals: 18, // Different decimals
        },
      });

      const request = createSettlementRequest({
        paymentRequirements: {
          ...TEST_PAYMENT_REQUIREMENTS,
          amount: '1000000000000000000', // 1e18 = $1.00 with 18 decimals
        },
      });

      const response = await issuer.settle(request);

      expect(response.payment_receipt.amountUSDC).toBe(1.0);
      expect(response.extensions.zk_credential.credential.tier).toBe(2);
    });
  });

  describe('commitment validation', () => {
    it('should reject unsupported scheme prefix', async () => {
      const issuer = createIssuer();
      const request = createSettlementRequest({
        extensions: {
          zk_credential: {
            commitment: `unsupported-scheme:0x04${TEST_COMMITMENT_X}${TEST_COMMITMENT_Y}`,
          },
        },
      });

      await expect(issuer.settle(request)).rejects.toThrow('Unsupported scheme: unsupported-scheme');
    });

    it('should reject commitment without 04 prefix', async () => {
      const issuer = createIssuer();
      const request = createSettlementRequest({
        extensions: {
          zk_credential: {
            // Missing 04 prefix for uncompressed point
            commitment: `pedersen-schnorr-poseidon-ultrahonk:0x${TEST_COMMITMENT_X}${TEST_COMMITMENT_Y}`,
          },
        },
      });

      await expect(issuer.settle(request)).rejects.toThrow('Invalid commitment format');
    });

    it('should reject commitment with wrong length', async () => {
      const issuer = createIssuer();
      const request = createSettlementRequest({
        extensions: {
          zk_credential: {
            commitment: `pedersen-schnorr-poseidon-ultrahonk:0x04${TEST_COMMITMENT_X}`, // Missing Y coordinate
          },
        },
      });

      await expect(issuer.settle(request)).rejects.toThrow('Invalid commitment format');
    });

    it('should reject commitment with invalid hex', async () => {
      const issuer = createIssuer();
      const request = createSettlementRequest({
        extensions: {
          zk_credential: {
            commitment: `pedersen-schnorr-poseidon-ultrahonk:0x04${'z'.repeat(64)}${'x'.repeat(64)}`,
          },
        },
      });

      // This should fail during hex parsing
      await expect(issuer.settle(request)).rejects.toThrow();
    });
  });

  describe('payment verification failures', () => {
    it('should reject when payment verification fails', async () => {
      const issuer = createIssuer();
      mockEvmScheme.verify.mockResolvedValue({
        isValid: false,
        invalidReason: 'Signature verification failed',
      });

      const request = createSettlementRequest();

      await expect(issuer.settle(request)).rejects.toThrow(
        'Payment verification failed: Signature verification failed'
      );
      expect(mockEvmScheme.settle).not.toHaveBeenCalled();
    });

    it('should reject when payment settlement fails', async () => {
      const issuer = createIssuer();
      mockEvmScheme.settle.mockResolvedValue({
        success: false,
        errorReason: 'Insufficient balance',
      });

      const request = createSettlementRequest();

      await expect(issuer.settle(request)).rejects.toThrow(
        'Payment settlement failed: Insufficient balance'
      );
    });

    it('should reject when EVM scheme is not configured', async () => {
      const config: IssuerConfig = {
        serviceId: TEST_SERVICE_ID,
        secretKey: TEST_SECRET_KEY,
        tiers: TEST_TIERS,
        // No evmPayment configured
      };
      const issuer = new CredentialIssuer(config);

      const request = createSettlementRequest();

      await expect(issuer.settle(request)).rejects.toThrow('EVM payment scheme not configured');
    });
  });

  describe('tier assignment', () => {
    it('should reject payment below minimum tier', async () => {
      const issuer = createIssuer();
      const request = createSettlementRequest({
        paymentRequirements: {
          ...TEST_PAYMENT_REQUIREMENTS,
          amount: '1000', // $0.001 USDC - below $0.10 minimum
        },
      });

      await expect(issuer.settle(request)).rejects.toThrow('below minimum tier');
    });

    it('should assign correct tier at exact boundary', async () => {
      const issuer = createIssuer();

      // Exactly $0.10 (10 cents)
      const request = createSettlementRequest({
        paymentRequirements: {
          ...TEST_PAYMENT_REQUIREMENTS,
          amount: '100000', // Exactly 10 cents
        },
      });

      const response = await issuer.settle(request);
      expect(response.extensions.zk_credential.credential.tier).toBe(1);
    });

    it('should assign highest qualifying tier', async () => {
      const issuer = createIssuer({
        tiers: [
          { minAmountCents: 500, tier: 3, presentationBudget: 100, durationSeconds: 604800 }, // $5.00
          { minAmountCents: 100, tier: 2, presentationBudget: 50, durationSeconds: 86400 },   // $1.00
          { minAmountCents: 10, tier: 1, presentationBudget: 10, durationSeconds: 3600 },     // $0.10
        ],
      });

      // $2.50 should get tier 2 (between $1 and $5)
      const request = createSettlementRequest({
        paymentRequirements: {
          ...TEST_PAYMENT_REQUIREMENTS,
          amount: '2500000', // $2.50
        },
      });

      const response = await issuer.settle(request);
      expect(response.extensions.zk_credential.credential.tier).toBe(2);
      expect(response.extensions.zk_credential.credential.presentation_budget).toBe(50);
    });
  });

  describe('credential structure', () => {
    it('should include correct service_id as hex', async () => {
      const issuer = createIssuer({ serviceId: 42n });
      const request = createSettlementRequest();

      const response = await issuer.settle(request);

      // 42n should be padded to 32 bytes hex
      expect(response.extensions.zk_credential.credential.service_id).toBe(
        '0x000000000000000000000000000000000000000000000000000000000000002a'
      );
    });

    it('should preserve commitment in response', async () => {
      const issuer = createIssuer();
      const request = createSettlementRequest();

      const response = await issuer.settle(request);

      expect(response.extensions.zk_credential.credential.commitment).toBe(
        `pedersen-schnorr-poseidon-ultrahonk:0x04${TEST_COMMITMENT_X}${TEST_COMMITMENT_Y}`
      );
    });

    it('should generate valid signature format', async () => {
      const issuer = createIssuer();
      const request = createSettlementRequest();

      const response = await issuer.settle(request);

      // Signature should be r.x (64 hex) + r.y (64 hex) + s (64 hex) = 192 hex chars
      const sig = response.extensions.zk_credential.credential.signature;
      expect(sig).toMatch(/^0x[a-f0-9]{192}$/);
      expect(sig.length).toBe(2 + 192); // 0x prefix + 192 hex chars
    });
  });
});
