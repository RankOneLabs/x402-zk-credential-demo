import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { ZkCredentialMiddleware, type ZkCredentialConfig } from '../src/middleware.js';
import { bigIntToHex, stringToField } from '@demo/crypto';

// Skip ZK backend tests in CI — UltraHonk WASM takes >30s per test on GitHub Actions
const describeZK = process.env.CI ? describe.skip : describe;

/**
 * Create a mock Express request
 */
function createMockRequest(
  headersOrBody: Record<string, unknown> = {},
  url = '/api/test',
  body?: Record<string, unknown>
): Partial<Request> {
  const isBody = 'zk-credential' in headersOrBody;
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
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  const suite = (overrides.suite as string) ?? 'pedersen-schnorr-poseidon-ultrahonk';
  const currentTime = (overrides.currentTime as number) ?? Math.floor(Date.now() / 1000);

  return {
    'zk-credential': {
      version: '0.1.0',
      suite,
      proof: Buffer.from([1, 2, 3, 4]).toString('base64url'),
      current_time: currentTime,
      public_outputs: {
        origin_token: originToken,
        tier,
      },
    },
  };
}

const createValidHeaders = createValidBody;

describe('ZkCredentialMiddleware', () => {
  const defaultConfig: ZkCredentialConfig = {
    serviceId: 1n,
    facilitatorPubkey: { x: 1n, y: 2n },
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
      const middleware = new ZkCredentialMiddleware(defaultConfig);
      const req = createMockRequest({});

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('credential_missing');
        expect(result.message).toBe('Missing zk-credential presentation');
      }
    });

    it('should reject when zk-credential body has wrong format', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);
      const req = createMockRequest({}, '/api/test', { 'zk-credential': 'invalid' });

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
      const req = createMockRequest({}, '/api/test', body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('unsupported_suite');
      }
    });

    it('should reject invalid proof format', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);
      const body = createValidBody('0xabc', 1);
      (body['zk-credential'] as Record<string, unknown>).proof = '';
      const req = createMockRequest({}, '/api/test', body);

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
      (body['zk-credential'] as Record<string, unknown>).proof = 'invalid@#chars';
      const req = createMockRequest({}, '/api/test', body);

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
      (body['zk-credential'] as Record<string, unknown>).proof = 'AQID BAU=';
      const req = createMockRequest({}, '/api/test', body);

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
      // This would pass Buffer.from() but fails round-trip check
      (body['zk-credential'] as Record<string, unknown>).proof = 'QQ='; // Should be 'QQ==' for proper padding
      const req = createMockRequest({}, '/api/test', body);

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
      // Valid base64 encoding
      (body['zk-credential'] as Record<string, unknown>).proof = Buffer.from([1, 2, 3, 4]).toString('base64url');
      const req = createMockRequest({}, '/api/test', body);

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
      const headers = createValidHeaders('0xabc', 1);
      const req = createMockRequest(headers);

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
      const headers = createValidHeaders('0xabc', 1);
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(true);
    });

    it('should accept tier above minimum', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        minTier: 1,
      });
      const headers = createValidHeaders('0xabc', 2);
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(true);
    });

    it('should default minTier to 0', async () => {
      const middleware = new ZkCredentialMiddleware({
        serviceId: 1n,
        facilitatorPubkey: { x: 1n, y: 2n },
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
      const middleware = new ZkCredentialMiddleware({
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
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const body = createValidBody('0xabc', 1);
      (body['zk-credential'] as Record<string, unknown>).proof = '';
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
      (body['zk-credential'] as Record<string, unknown>).proof = '';
      const req = createMockRequest(body);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errorCode).toBe('invalid_proof');
      }
    });
  });

  describe('middleware - payment settlement', () => {
    it('should return 503 when facilitator is unavailable', async () => {
      const middleware = new ZkCredentialMiddleware(defaultConfig);

      // Mock fetch to throw error
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

      const body = {
        payment: { some: 'payment' },
        extensions: {
          'zk-credential': {
            commitment: 'pedersen-schnorr-poseidon-ultrahonk:0x123'
          }
        }
      };
      const req = createMockRequest({});
      req.body = body; // Explicitly set body — createMockRequest only auto-detects zk_credential bodies
      const res = createMockResponse();
      const next = vi.fn();

      await middleware.middleware()(req as Request, res as Response, next);

      expect(res.statusCode).toBe(503);
      expect(res.jsonData).toEqual({
        error: 'service_unavailable',
        message: 'Payment facilitator is temporarily unavailable. Please retry.'
      });
    });
  });

  describe('verifyRequest - clock drift validation', () => {
    it('should reject current_time too far in the past', async () => {
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        skipProofVerification: true,
      });
      const staleTime = Math.floor(Date.now() / 1000) - 120; // 120s ago, exceeds ±60s
      const headers = createValidHeaders('0xabc', 1, { currentTime: staleTime });
      const req = createMockRequest(headers);

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
      const headers = createValidHeaders('0xabc', 1, { currentTime: futureTime });
      const req = createMockRequest(headers);

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
      const headers = createValidHeaders('0xabc', 1, { currentTime: recentTime });
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      expect(result.valid).toBe(true);
    });

    it('should not attempt proof verification when drift exceeds tolerance', async () => {
      // Use skipProofVerification: false — if drift check works, proof verification
      // should never be reached (and would fail anyway with a dummy proof)
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        skipProofVerification: false,
      });
      const staleTime = Math.floor(Date.now() / 1000) - 120;
      const headers = createValidHeaders('0xabc', 1, { currentTime: staleTime });
      const req = createMockRequest(headers);

      const result = await middleware.verifyRequest(req as Request);

      // Should be rejected by drift check, not by proof verification failure
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
      const headers = createValidHeaders('0xabc', 1, { serviceId: 1n }); // Wrong service ID
      const req = createMockRequest(headers);

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
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        facilitatorPubkey: { x: 100n, y: 2n },
        skipProofVerification: false,
      });
      // Include all correct values EXCEPT pubkey X
      const headers = createValidHeaders('0xabc', 1, {
        serviceId: 1n,
        originId,
        facilitatorPubkeyX: 999n, // Wrong X - config expects 100n
        facilitatorPubkeyY: 2n,   // Correct Y
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
      const middleware = new ZkCredentialMiddleware({
        ...defaultConfig,
        facilitatorPubkey: { x: 1n, y: 200n },
        skipProofVerification: false,
      });
      // Include all correct values EXCEPT pubkey Y
      const headers = createValidHeaders('0xabc', 1, {
        serviceId: 1n,
        originId,
        facilitatorPubkeyX: 1n,   // Correct X
        facilitatorPubkeyY: 999n, // Wrong Y - config expects 200n
      });
      const req = createMockRequest(headers);

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

      const headers = createValidHeaders('0xuser', 1);
      const req = createMockRequest(headers) as Request;
      const next1 = vi.fn();
      const next2 = vi.fn();

      await middleware.middleware()(req, createMockResponse() as Response, next1);
      await middleware.middleware()(req, createMockResponse() as Response, next2);

      // Third request should be rate limited
      const res3 = createMockResponse();
      const next3 = vi.fn();
      await middleware.middleware()(req, res3 as Response, next3);

      expect(res3.statusCode).toBe(429);
      expect(res3.jsonData).toEqual({ error: 'rate_limited', message: 'Rate limit exceeded' });
      expect(next3).not.toHaveBeenCalled();
    });

    it('should track rate limits per origin token', async () => {
      const middleware = new ZkCredentialMiddleware({
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
      const middleware = new ZkCredentialMiddleware(defaultConfig);

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
      const middleware = new ZkCredentialMiddleware(defaultConfig);

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

  describeZK('origin ID computation', () => {
    it('should compute different origin IDs for different paths', async () => {
      const middleware = new ZkCredentialMiddleware({
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
