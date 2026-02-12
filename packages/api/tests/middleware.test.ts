import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { ZkCredentialMiddleware, type ZkCredentialConfig } from '../src/middleware.js';
import { stringToField, pointToBytes, toBase64Url } from '@demo/crypto';

// Skip ZK backend tests in CI — UltraHonk WASM takes >30s per test on GitHub Actions
const describeZK = process.env.CI ? describe.skip : describe;

/**
 * Create a mock Express request
 */
function createMockRequest(
  body?: Record<string, unknown>,
  url = '/api/test',
  customHeaders?: Record<string, string>
): Partial<Request> {
  const headersObj: Record<string, string> = {
    host: 'localhost:3000',
    ...customHeaders,
  };
  return {
    headers: headersObj,
    url,
    originalUrl: url, // Express sets originalUrl for route matching
    protocol: 'http',
    body,
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
 * Create valid ZK session presentation body (x402_zk_session envelope)
 */
function createValidBody(
  originToken: string,
  tier: number,
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  const suite = (overrides.suite as string) ?? 'pedersen-schnorr-poseidon-ultrahonk';
  const currentTime = (overrides.currentTime as number) ?? Math.floor(Date.now() / 1000);
  const issuerPubkey = (overrides.issuerPubkey as string) ?? toBase64Url(pointToBytes({ x: 1n, y: 2n }));

  return {
    x402_zk_credential: {
      version: '0.1.0',
      suite,
      issuer_pubkey: issuerPubkey,
      proof: Buffer.from([1, 2, 3, 4]).toString('base64url'),
      current_time: currentTime,
      public_outputs: {
        origin_token: originToken,
        tier,
      },
    },
    payload: null,
  };
}

/** Create mock request with valid zk-credential body */
function createAuthenticatedRequest(
  originToken: string,
  tier: number,
  url = '/api/test',
  overrides: Record<string, unknown> = {}
): Partial<Request> {
  const body = createValidBody(originToken, tier, overrides);
  return createMockRequest(body, url);
}

describe('ZkCredentialMiddleware', () => {
  const defaultConfig: ZkCredentialConfig = {
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
    it('should reject when x402_zk_credential body is missing', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);
      const req = createMockRequest({});

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('credential_missing');
        expect(result.message).toBe('Missing zk-credential presentation');
      }
    });

    it('should reject when x402_zk_credential body has wrong format', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);
      const req = createMockRequest({ x402_zk_credential: 'invalid' });

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('credential_missing');
        expect(result.message).toBe('Missing zk-credential presentation');
      }
    });

    it('should reject unsupported suite', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);
      const body = createValidBody('0xabc', 1, { suite: 'unsupported-suite' });
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('unsupported_suite');
      }
    });

    it('should reject invalid proof format', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);
      const body = createValidBody('0xabc', 1);
      (body.x402_zk_credential as Record<string, unknown>).proof = '';
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
        expect(result.message).toBe('Invalid proof encoding');
      }
    });

    it('should reject malformed base64 with invalid characters', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);
      const body = createValidBody('0xabc', 1);
      // Invalid characters like @ and # are not valid in base64
      (body.x402_zk_credential as Record<string, unknown>).proof = 'invalid@#chars';
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
        expect(result.message).toBe('Invalid proof encoding');
      }
    });

    it('should reject base64 with spaces', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);
      const body = createValidBody('0xabc', 1);
      // Spaces are not valid in strict base64
      (body.x402_zk_credential as Record<string, unknown>).proof = 'AQID BAU=';
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
        expect(result.message).toBe('Invalid proof encoding');
      }
    });

    it('should reject base64 with incorrect padding', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);
      const body = createValidBody('0xabc', 1);
      (body.x402_zk_credential as Record<string, unknown>).proof = 'QQ='; // Should be 'QQ==' for proper padding
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
        expect(result.message).toBe('Invalid proof encoding');
      }
    });

    it('should accept valid base64 proof', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);
      const body = createValidBody('0xabc', 1);
      (body.x402_zk_credential as Record<string, unknown>).proof = Buffer.from([1, 2, 3, 4]).toString('base64url');
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      // Should pass base64 validation and proceed to other checks
      // (In skip mode, it should succeed)
      expect(result.valid).toBe(true);
    });
  });

  describe('verifyRequest - minimum tier enforcement', () => {
    it('should reject tier below minimum', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        minTier: 2,
      });
      const req = createAuthenticatedRequest('0xabc', 1);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('tier_insufficient');
      }
    });

    it('should accept tier at minimum', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        minTier: 1,
      });
      const req = createAuthenticatedRequest('0xabc', 1);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(true);
    });

    it('should accept tier above minimum', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        minTier: 1,
      });
      const req = createAuthenticatedRequest('0xabc', 2);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(true);
    });

    it('should default minTier to 0', async () => {
      const middleware = new ZkCredentialMiddleware({
        serviceId: 1n,
        issuerPubkey: { x: 1n, y: 2n },
        rateLimit: { maxRequestsPerToken: 100, windowSeconds: 60 },
        skipProofVerification: true,
        facilitatorUrl: 'http://localhost:3001/settle',
      });
      const req = createAuthenticatedRequest('0xabc', 0);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(true);
    });
  });

  describe('verifyRequest - skip verification mode', () => {
    it('should return valid with tier and token in skip mode', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        skipProofVerification: true,
      });
      const req = createAuthenticatedRequest('0xmytoken', 2);

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
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const body = createValidBody('0xabc', 1);
      (body.x402_zk_credential as Record<string, unknown>).proof = '';
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
      }
    });

    it('should reject invalid JSON in proof', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const body = createValidBody('0xabc', 1);
      (body.x402_zk_credential as Record<string, unknown>).proof = '';
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
      }
    });
  });

  describe('middleware - missing redemption envelope', () => {
    it('should return 402 when x402_zk_credential is missing', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);
      const req = createMockRequest({ payment: { some: 'payment' } }, '/api/test');
      const res = createMockResponse();
      const next = vi.fn();

      await middleware.middleware()(req as Request, res as Response, next);

      expect(res.statusCode).toBe(402);
      expect((res.jsonData as Record<string, unknown>).x402Version).toBe(2);
    });
  });

  describe('verifyRequest - clock drift validation', () => {
    it('should reject current_time too far in the past', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        skipProofVerification: true,
      });
      const staleTime = Math.floor(Date.now() / 1000) - 120; // 120s ago, exceeds ±60s
      const req = createAuthenticatedRequest('0xabc', 1, '/api/test', { currentTime: staleTime });

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
        expect(result.message).toContain('drift');
      }
    });

    it('should reject current_time too far in the future', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        skipProofVerification: true,
      });
      const futureTime = Math.floor(Date.now() / 1000) + 120; // 120s ahead
      const req = createAuthenticatedRequest('0xabc', 1, '/api/test', { currentTime: futureTime });

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
        expect(result.message).toContain('drift');
      }
    });

    it('should accept current_time within drift tolerance', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        skipProofVerification: true,
      });
      // 30s ago — well within ±60s
      const recentTime = Math.floor(Date.now() / 1000) - 30;
      const req = createAuthenticatedRequest('0xabc', 1, '/api/test', { currentTime: recentTime });

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(true);
    });

    it('should not attempt proof verification when drift exceeds tolerance', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const staleTime = Math.floor(Date.now() / 1000) - 120;
      const req = createAuthenticatedRequest('0xabc', 1, '/api/test', { currentTime: staleTime });

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
        expect(result.message).toContain('drift');
      }
    });
  });

  describeZK('verifyRequest - public input validation', () => {
    it('should reject mismatched service_id', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        serviceId: 42n,
        skipProofVerification: false,
      });
      const body = createValidBody('0xabc', 1, { serviceId: 1n });
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
      }
    });

    it('should reject mismatched origin_id', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const body = createValidBody('0xabc', 1, {
        originId: stringToField('/different/path')
      });
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
      }
    });

    it('should reject mismatched issuer pubkey X', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        issuerPubkey: { x: 100n, y: 2n },
        skipProofVerification: false,
      });
      const body = createValidBody('0xabc', 1, {
        issuerPubkey: toBase64Url(pointToBytes({ x: 999n, y: 2n })),
      });
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
      }
    });

    it('should reject mismatched issuer pubkey Y', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        issuerPubkey: { x: 1n, y: 200n },
        skipProofVerification: false,
      });
      const body = createValidBody('0xabc', 1, {
        issuerPubkey: toBase64Url(pointToBytes({ x: 1n, y: 999n })),
      });
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
      }
    });
  });

  describe('middleware - rate limiting', () => {
    it('should return 429 when rate limit exceeded', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        rateLimit: { maxRequestsPerToken: 2, windowSeconds: 60 },
      });

      // Each call needs a fresh request since middleware unwraps req.body
      const next1 = vi.fn();
      const next2 = vi.fn();

      await middleware.middleware()(createAuthenticatedRequest('0xuser', 1) as Request, createMockResponse() as Response, next1);
      await middleware.middleware()(createAuthenticatedRequest('0xuser', 1) as Request, createMockResponse() as Response, next2);

      // Third request should be rate limited
      const res3 = createMockResponse();
      const next3 = vi.fn();
      await middleware.middleware()(createAuthenticatedRequest('0xuser', 1) as Request, res3 as Response, next3);

      expect(res3.statusCode).toBe(429);
      expect(res3.jsonData).toEqual({ error: 'rate_limited', message: 'Rate limit exceeded' });
      expect(next3).not.toHaveBeenCalled();
    });

    it('should track rate limits per origin token', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        rateLimit: { maxRequestsPerToken: 2, windowSeconds: 60 },
      });

      // User 1 exhausts their limit (fresh request each call)
      await middleware.middleware()(createAuthenticatedRequest('0xuser1', 1) as Request, createMockResponse() as Response, vi.fn());
      await middleware.middleware()(createAuthenticatedRequest('0xuser1', 1) as Request, createMockResponse() as Response, vi.fn());
      const res1 = createMockResponse();
      await middleware.middleware()(createAuthenticatedRequest('0xuser1', 1) as Request, res1 as Response, vi.fn());
      expect(res1.statusCode).toBe(429);

      // User 2 should still have quota
      const res2 = createMockResponse();
      const next2 = vi.fn();
      await middleware.middleware()(createAuthenticatedRequest('0xuser2', 1) as Request, res2 as Response, next2);
      expect(next2).toHaveBeenCalled();
      expect(res2.statusCode).toBeUndefined(); // No error status set
    });
  });

  describe('getStats', () => {
    it('should return rate limiter statistics', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);

      // Fresh request each call since middleware unwraps req.body
      await middleware.middleware()(createAuthenticatedRequest('0xstats', 1) as Request, createMockResponse() as Response, vi.fn());
      await middleware.middleware()(createAuthenticatedRequest('0xstats', 1) as Request, createMockResponse() as Response, vi.fn());

      const stats = middleware.getStats();

      expect(stats.totalTokens).toBe(1);
      expect(stats.totalRequests).toBe(2);
    });

    it('should track multiple tokens', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);

      await middleware.middleware()(createAuthenticatedRequest('0xstats1', 1) as Request, createMockResponse() as Response, vi.fn());
      await middleware.middleware()(createAuthenticatedRequest('0xstats2', 1) as Request, createMockResponse() as Response, vi.fn());
      await middleware.middleware()(createAuthenticatedRequest('0xstats2', 1) as Request, createMockResponse() as Response, vi.fn());

      const stats = middleware.getStats();

      expect(stats.totalTokens).toBe(2);
      expect(stats.totalRequests).toBe(3);
    });
  });

  describeZK('origin ID computation', () => {
    it('should compute different origin IDs for different paths', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });

      const body = createValidBody('0xabc', 1, {
        originId: stringToField('/api/test'),
      });

      // Request to /api/other should fail origin ID check
      const req = createMockRequest(body, '/api/other');
      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
      }

      await middleware.destroy();
    });
  });

  describe('destroy', () => {
    it('should clean up interval timer', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);

      // Should not throw
      await middleware.destroy();
    });

    it('should be safe to call destroy multiple times', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);

      await middleware.destroy();
      await middleware.destroy();
      await middleware.destroy();

      // Should not throw
    });
  });
});
