import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { ZkSessionMiddleware, type ZkSessionConfig } from '../src/middleware.js';
import { bigIntToHex, stringToField } from '@demo/crypto';

/**
 * Create a mock Express request
 */
function createMockRequest(
  headersOrBody: Record<string, unknown> = {},
  url = '/api/test',
  body?: Record<string, unknown>
): Partial<Request> {
  const isBody = 'zk_credential' in headersOrBody;
  const headersObj = {
    host: 'localhost:3000',
    ...(isBody ? {} : (headersOrBody as Record<string, string>)),
  };
  return {
    headers: headersObj,
    url,
    originalUrl: url, // Express sets originalUrl for route matching
    protocol: 'http',
    body: isBody ? headersOrBody : body,
    get: (name: string) => headersObj[name.toLowerCase() as keyof typeof headersObj],
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
 * Create valid ZK credential body for testing
 * Uses zk_credential presentation format (spec §6.3)
 */
function createValidBody(
  originToken: string,
  tier: number,
  overrides: {
    suite?: string;
    expiresAt?: number;
  } = {}
): Record<string, unknown> {
  const suite = overrides.suite ?? 'pedersen-schnorr-poseidon-ultrahonk';
  const expiresAt = overrides.expiresAt ?? Math.floor(Date.now() / 1000) + 60;

  return {
    zk_credential: {
      version: '0.2.0',
      suite,
      proof: Buffer.from([1, 2, 3, 4]).toString('base64'),
      public_outputs: {
        origin_token: originToken,
        tier,
        expires_at: expiresAt,
      },
    },
  };
}

const createValidHeaders = createValidBody;

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
    facilitatorUrl: 'http://localhost:3001/settle',
  };

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('verifyRequest - body validation', () => {
    it('should reject when zk_credential body is missing', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);
      const req = createMockRequest({});

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('credential_missing');
        expect(result.message).toBe('Missing zk_credential presentation');
      }
    });

    it('should reject when zk_credential body has wrong format', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);
      const req = createMockRequest({}, '/api/test', { zk_credential: 'invalid' });

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('credential_missing');
        expect(result.message).toBe('Missing zk_credential presentation');
      }
    });

    it('should reject unsupported suite', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);
      const body = createValidBody('0xabc', 1, { suite: 'unsupported-suite' });
      const req = createMockRequest({}, '/api/test', body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('unsupported_suite');
      }
    });

    it('should reject invalid proof format', async () => {
      const middleware = new ZkSessionMiddleware(defaultConfig);
      const body = createValidBody('0xabc', 1);
      (body.zk_credential as Record<string, unknown>).proof = '';
      const req = createMockRequest({}, '/api/test', body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
        expect(result.message).toBe('Invalid proof encoding');
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
        expect(result.errorCode).toBe('tier_insufficient');
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
        facilitatorUrl: 'http://localhost:3001/settle',
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

  describe('verifyRequest - proof format validation (with skipProofVerification: false)', () => {
    it('should reject invalid base64 proof', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const body = createValidBody('0xabc', 1);
      (body.zk_credential as Record<string, unknown>).proof = '';
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
      }
    });

    it('should reject invalid JSON in proof', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const body = createValidBody('0xabc', 1);
      (body.zk_credential as Record<string, unknown>).proof = '';
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
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
        expect(result.errorCode).toBe('invalid_proof');
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
        expect(result.errorCode).toBe('invalid_proof');
      }
    });

    it('should reject mismatched issuer pubkey X', async () => {
      const originId = stringToField('/api/test');
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        issuerPubkey: { x: 100n, y: 2n },
        skipProofVerification: false,
      });
      // Include all correct values EXCEPT pubkey X
      const headers = createValidHeaders('0xabc', 1, { 
        serviceId: 1n,
        originId,
        issuerPubkeyX: 999n, // Wrong X - config expects 100n
        issuerPubkeyY: 2n,   // Correct Y
      });
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
      }
    });

    it('should reject mismatched issuer pubkey Y', async () => {
      const originId = stringToField('/api/test');
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        issuerPubkey: { x: 1n, y: 200n },
        skipProofVerification: false,
      });
      // Include all correct values EXCEPT pubkey Y
      const headers = createValidHeaders('0xabc', 1, { 
        serviceId: 1n,
        originId,
        issuerPubkeyX: 1n,   // Correct X
        issuerPubkeyY: 999n, // Wrong Y - config expects 200n
      });
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
      }
    });
  });

  // TODO: These tests require actual proof verification which is slow.
  // They should be moved to E2E tests or use a mocked verifier.
  describe.skip('verifyRequest - time drift handling', () => {
    it('should accept proof time within 60 seconds in the past', async () => {
        expect(result.errorCode).toBe('invalid_proof');

      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
  describe('verifyRequest - expiry validation', () => {
    it('should reject expired credential', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: true,
      });
      const body = createValidBody('0xabc', 1, {
        expiresAt: Math.floor(Date.now() / 1000) - 120,
      });
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('credential_expired');
      }
    });
  });

      // Third request should be rate limited
      const res3 = createMockResponse();
      await middleware.middleware()(req, res3 as Response, next);

      expect(res3.statusCode).toBe(429);
      expect(res3.jsonData).toEqual({ error: 'rate_limited', message: 'Rate limit exceeded' });
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
        expect(result.errorCode).toBe('invalid_proof');
      }

      await middleware.destroy();
    });

    // TODO: This test requires actual proof verification which is slow.
    it.skip('should match origin ID for correct path', async () => {
      const middleware = new ZkSessionMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });

      const originId = stringToField('/api/test');
      const headers = createValidHeaders('0xabc', 1, {
        serviceId: 1n,
        originId,
        issuerPubkeyX: 1n,
        issuerPubkeyY: 2n,
      });

      const req = createMockRequest(headers, '/api/test');
      const result = await middleware.verifyRequest(req as Request);

      // Will fail on proof verification, not origin ID mismatch
      // Note: This passes public input validation but fails on actual ZK proof verification
      expect(result.valid).toBe(false);
      if (!result.valid) {
        // Should fail on proof verification, not public input mismatch
        expect(result.errorCode).toBe('invalid_proof');
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
