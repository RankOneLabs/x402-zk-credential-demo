import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { ZkSessionMiddleware, type ZkSessionConfig } from '../src/middleware.js';
import { bigIntToHex, stringToField } from '@demo/crypto';

/**
 * Create a mock Express request
 */
function createMockRequest(headers: Record<string, string> = {}, url = '/api/test'): Partial<Request> {
  return {
    headers: {
      host: 'localhost:3000',
      ...headers,
    },
    url,
  };
}

/**
 * Create a mock Express response
 */
function createMockResponse(): Partial<Response> & {
  statusCode?: number;
  jsonData?: unknown;
  headers: Record<string, string>;
} {
  const res: Partial<Response> & {
    statusCode?: number;
    jsonData?: unknown;
    headers: Record<string, string>;
  } = {
    headers: {},
    statusCode: undefined,
    jsonData: undefined,
  };

  res.status = vi.fn((code: number) => {
    res.statusCode = code;
    return res as Response;
  });

  res.json = vi.fn((data: unknown) => {
    res.jsonData = data;
    return res as Response;
  });

  res.set = vi.fn((key: string, value: string) => {
    res.headers[key] = value;
    return res as Response;
  });

  return res;
}

/**
 * Create valid ZK session headers for testing
 */
function createValidHeaders(
  originToken: string,
  tier: number,
  overrides: {
    serviceId?: bigint;
    currentTime?: bigint;
    originId?: bigint;
    issuerPubkeyX?: bigint;
    issuerPubkeyY?: bigint;
  } = {}
): Record<string, string> {
  const proofData = {
    proof: Buffer.from([1, 2, 3, 4]).toString('base64'),
    publicInputs: [
      bigIntToHex(overrides.serviceId ?? 1n),
      bigIntToHex(overrides.currentTime ?? BigInt(Math.floor(Date.now() / 1000))),
      bigIntToHex(overrides.originId ?? stringToField('/api/test')),
      bigIntToHex(overrides.issuerPubkeyX ?? 1n),
      bigIntToHex(overrides.issuerPubkeyY ?? 2n),
      originToken,
      `0x${tier.toString(16)}`,
    ],
  };

  return {
    'zk-session-proof': Buffer.from(JSON.stringify(proofData)).toString('base64'),
    'zk-session-token': originToken,
    'zk-session-tier': tier.toString(),
  };
}

describe('ZkSessionMiddleware', () => {
  const defaultConfig: ZkSessionConfig = {
    serviceId: 1n,
    issuerPubkey: { x: 1n, y: 2n },
    rateLimit: {
      maxRequestsPerToken: 100,
      windowSeconds: 60,
    },
    minTier: 0,
    skipProofVerification: true, // Skip actual ZK verification in unit tests
  };

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('verifyRequest - header validation', () => {
    it('should reject when all ZK headers are missing', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);
      const req = createMockRequest({});

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Missing ZK session headers');
      }
    });

    it('should reject when proof header is missing', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);
      const req = createMockRequest({
        'zk-session-token': '0xabc',
        'zk-session-tier': '1',
      });

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Missing ZK session headers');
      }
    });

    it('should reject when token header is missing', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);
      const req = createMockRequest({
        'zk-session-proof': 'someproof',
        'zk-session-tier': '1',
      });

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Missing ZK session headers');
      }
    });

    it('should reject when tier header is missing', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);
      const req = createMockRequest({
        'zk-session-proof': 'someproof',
        'zk-session-token': '0xabc',
      });

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Missing ZK session headers');
      }
    });

    it('should reject when tier is not a number', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);
      const req = createMockRequest({
        'zk-session-proof': 'someproof',
        'zk-session-token': '0xabc',
        'zk-session-tier': 'not-a-number',
      });

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Invalid tier');
      }
    });

    it('should reject negative tier values', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        minTier: 0,
      });
      const req = createMockRequest({
        'zk-session-proof': 'someproof',
        'zk-session-token': '0xabc',
        'zk-session-tier': '-1',
      });

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Tier -1 below minimum 0');
      }
    });
  });

  describe('verifyRequest - minimum tier enforcement', () => {
    it('should reject tier below minimum', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        minTier: 2,
      });
      const headers = createValidHeaders('0xabc', 1);
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Tier 1 below minimum 2');
      }
    });

    it('should accept tier at minimum', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        minTier: 1,
      });
      const headers = createValidHeaders('0xabc', 1);
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(true);
    });

    it('should accept tier above minimum', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        minTier: 1,
      });
      const headers = createValidHeaders('0xabc', 2);
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(true);
    });

    it('should default minTier to 0', async () => {
      const middleware = new ZkSessionMiddleware({
        serviceId: 1n,
        issuerPubkey: { x: 1n, y: 2n },
        rateLimit: { maxRequestsPerToken: 100, windowSeconds: 60 },
        skipProofVerification: true,
      });
      const headers = createValidHeaders('0xabc', 0);
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(true);
    });
  });

  describe('verifyRequest - skip verification mode', () => {
    it('should return valid with tier and token in skip mode', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: true,
      });
      const headers = createValidHeaders('0xmytoken', 2);
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.tier).toBe(2);
        expect(result.originToken).toBe('0xmytoken');
      }
    });
  });

  describe('verifyRequest - proof format validation', () => {
    it('should reject invalid base64 proof', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const req = createMockRequest({
        'zk-session-proof': 'not-valid-base64!!!',
        'zk-session-token': '0xabc',
        'zk-session-tier': '1',
      });

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Invalid proof format');
      }
    });

    it('should reject invalid JSON in proof', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const invalidProof = Buffer.from('not json').toString('base64');
      const req = createMockRequest({
        'zk-session-proof': invalidProof,
        'zk-session-token': '0xabc',
        'zk-session-tier': '1',
      });

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Invalid proof format');
      }
    });
  });

  describe('verifyRequest - public input validation', () => {
    it('should reject mismatched service_id', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        serviceId: 42n,
        skipProofVerification: false,
      });
      const headers = createValidHeaders('0xabc', 1, { serviceId: 1n }); // Wrong service ID
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Public input mismatch at index 0');
      }
    });

    it('should reject mismatched origin_id', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const headers = createValidHeaders('0xabc', 1, {
        originId: stringToField('/different/path')
      });
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Public input mismatch at index 2');
      }
    });

    it('should reject mismatched issuer pubkey X', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        issuerPubkey: { x: 100n, y: 2n },
        skipProofVerification: false,
      });
      const headers = createValidHeaders('0xabc', 1, { issuerPubkeyX: 1n }); // Wrong X
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Public input mismatch at index 3');
      }
    });

    it('should reject mismatched issuer pubkey Y', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        issuerPubkey: { x: 1n, y: 200n },
        skipProofVerification: false,
      });
      const headers = createValidHeaders('0xabc', 1, { issuerPubkeyY: 2n }); // Wrong Y
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Public input mismatch at index 4');
      }
    });
  });

  describe('verifyRequest - time drift handling', () => {
    it('should accept proof time within 60 seconds in the past', async () => {
      vi.useRealTimers(); // Need real time for this test

      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const currentTime = BigInt(Math.floor(Date.now() / 1000));
      const proofTime = currentTime - 30n; // 30 seconds ago
      const headers = createValidHeaders('0xabc', 1, { currentTime: proofTime });
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      // Should pass time check (drift is within 60s past)
      // Will fail on proof verification since we don't have real proof
      // But it shouldn't fail on time mismatch
      if (!result.valid) {
        expect(result.error).not.toBe('Public input mismatch at index 1');
      }
    });

    it('should reject proof time > 60 seconds in the past', async () => {
      vi.useRealTimers(); // Need real time for this test

      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const currentTime = BigInt(Math.floor(Date.now() / 1000));
      const proofTime = currentTime - 120n; // 2 minutes ago
      const headers = createValidHeaders('0xabc', 1, { currentTime: proofTime });
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Public input mismatch at index 1');
      }
    });

    it('should accept future proof time within 5 seconds (clock skew)', async () => {
      vi.useRealTimers(); // Need real time for this test

      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const currentTime = BigInt(Math.floor(Date.now() / 1000));
      const proofTime = currentTime + 3n; // 3 seconds in future (within 5s tolerance)
      const headers = createValidHeaders('0xabc', 1, { currentTime: proofTime });
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      // Should pass time check (within 5s future tolerance)
      if (!result.valid) {
        expect(result.error).not.toBe('Public input mismatch at index 1');
      }
    });

    it('should reject future proof time > 5 seconds (prevents pre-generation)', async () => {
      vi.useRealTimers(); // Need real time for this test

      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const currentTime = BigInt(Math.floor(Date.now() / 1000));
      const proofTime = currentTime + 30n; // 30 seconds in future
      const headers = createValidHeaders('0xabc', 1, { currentTime: proofTime });
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      // Should reject - future time beyond 5s tolerance prevents pre-generation attacks
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Public input mismatch at index 1');
      }
    });
  });

  describe('middleware() - Express integration', () => {
    it('should call next() on valid request', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);
      const headers = createValidHeaders('0xabc', 1);
      const req = createMockRequest(headers) as Request;
      const res = createMockResponse() as Response;
      const next = vi.fn();

      await middleware.middleware()(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.zkSession).toEqual({
        tier: 1,
        originToken: '0xabc',
      });
    });

    it('should return 401 on invalid request', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);
      const req = createMockRequest({}) as Request;
      const res = createMockResponse();
      const next = vi.fn();

      await middleware.middleware()(req, res as Response, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.statusCode).toBe(401);
      expect(res.jsonData).toEqual({ error: 'Missing ZK session headers' });
    });

    it('should set rate limit headers', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        rateLimit: { maxRequestsPerToken: 50, windowSeconds: 60 },
      });
      const headers = createValidHeaders('0xratelimit', 1);
      const req = createMockRequest(headers) as Request;
      const res = createMockResponse();
      const next = vi.fn();

      await middleware.middleware()(req, res as Response, next);

      expect(res.headers['X-RateLimit-Limit']).toBe('50');
      expect(res.headers['X-RateLimit-Remaining']).toBe('49');
      expect(res.headers['X-RateLimit-Reset']).toBeDefined();
    });

    it('should return 429 when rate limit exceeded', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        rateLimit: { maxRequestsPerToken: 2, windowSeconds: 60 },
      });
      const headers = createValidHeaders('0xlimited', 1);
      const req = createMockRequest(headers) as Request;
      const res = createMockResponse();
      const next = vi.fn();

      // Exhaust rate limit
      await middleware.middleware()(req, res as Response, vi.fn());
      await middleware.middleware()(req, createMockResponse() as Response, vi.fn());

      // Third request should be rate limited
      const res3 = createMockResponse();
      await middleware.middleware()(req, res3 as Response, next);

      expect(res3.statusCode).toBe(429);
      expect(res3.jsonData).toEqual({ error: 'Rate limit exceeded' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should track rate limits per origin token', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        rateLimit: { maxRequestsPerToken: 2, windowSeconds: 60 },
      });

      const headers1 = createValidHeaders('0xuser1', 1);
      const headers2 = createValidHeaders('0xuser2', 1);
      const req1 = createMockRequest(headers1) as Request;
      const req2 = createMockRequest(headers2) as Request;

      // User 1 exhausts their limit
      await middleware.middleware()(req1, createMockResponse() as Response, vi.fn());
      await middleware.middleware()(req1, createMockResponse() as Response, vi.fn());
      const res1 = createMockResponse();
      await middleware.middleware()(req1, res1 as Response, vi.fn());
      expect(res1.statusCode).toBe(429);

      // User 2 should still have quota
      const res2 = createMockResponse();
      const next2 = vi.fn();
      await middleware.middleware()(req2, res2 as Response, next2);
      expect(next2).toHaveBeenCalled();
      expect(res2.statusCode).toBeUndefined(); // No error status set
    });
  });

  describe('getStats', () => {
    it('should return rate limiter statistics', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);

      // Make some requests
      const headers = createValidHeaders('0xstats', 1);
      const req = createMockRequest(headers) as Request;
      await middleware.middleware()(req, createMockResponse() as Response, vi.fn());
      await middleware.middleware()(req, createMockResponse() as Response, vi.fn());

      const stats = middleware.getStats();

      expect(stats.totalTokens).toBe(1);
      expect(stats.totalRequests).toBe(2);
    });

    it('should track multiple tokens', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);

      const headers1 = createValidHeaders('0xstats1', 1);
      const headers2 = createValidHeaders('0xstats2', 1);
      const req1 = createMockRequest(headers1) as Request;
      const req2 = createMockRequest(headers2) as Request;

      await middleware.middleware()(req1, createMockResponse() as Response, vi.fn());
      await middleware.middleware()(req2, createMockResponse() as Response, vi.fn());
      await middleware.middleware()(req2, createMockResponse() as Response, vi.fn());

      const stats = middleware.getStats();

      expect(stats.totalTokens).toBe(2);
      expect(stats.totalRequests).toBe(3);
    });
  });

  describe('origin ID computation', () => {
    it('should compute different origin IDs for different paths', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });

      // Create headers with origin_id for /api/test
      const headers = createValidHeaders('0xabc', 1, {
        originId: stringToField('/api/test'),
      });

      // Request to /api/other should fail origin ID check
      const req = createMockRequest(headers, '/api/other');
      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe('Public input mismatch at index 2');
      }

      await middleware.destroy();
    });

    it('should match origin ID for correct path', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });

      const headers = createValidHeaders('0xabc', 1, {
        originId: stringToField('/api/test'),
      });

      const req = createMockRequest(headers, '/api/test');
      const result = await middleware.verifyRequest(req as Request);

      // Will fail on proof verification, not origin ID mismatch
      if (!result.valid) {
        expect(result.error).not.toBe('Public input mismatch at index 2');
      }

      await middleware.destroy();
    });
  });

  describe('destroy', () => {
    it('should clean up interval timer', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);

      // Should not throw
      await middleware.destroy();
    });

    it('should be safe to call destroy multiple times', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);

      await middleware.destroy();
      await middleware.destroy();
      await middleware.destroy();

      // Should not throw
    });
  });
});
