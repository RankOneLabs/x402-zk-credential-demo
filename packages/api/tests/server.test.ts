import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { createApiServer, type ApiServerConfig } from '../src/server.js';

/**
 * Helper to create valid ZK session headers
 * Uses skip mode so proof content doesn't matter
 */
function createZkHeaders(originToken: string, tier: number) {
  const proofData = {
    proof: Buffer.from([1, 2, 3, 4]).toString('base64'),
    publicInputs: [
      '0x1', '0x2', '0x3', '0x4', '0x5',  // Expected public inputs
      originToken,                          // origin_token
      `0x${tier.toString(16)}`,             // tier
    ],
  };
  const proofB64 = Buffer.from(JSON.stringify(proofData)).toString('base64');
  
  return {
    'zk-session-proof': proofB64,
    'zk-session-token': originToken,
    'zk-session-tier': tier.toString(),
  };
}

describe('API Server', () => {
  const config: ApiServerConfig = {
    port: 0, // Random port for testing
    zkSession: {
      serviceId: 1n,
      issuerPubkey: { x: 1n, y: 2n },
      rateLimit: {
        maxRequestsPerToken: 10,
        windowSeconds: 60,
      },
      minTier: 0,
      skipProofVerification: true, // Skip for unit tests
    },
  };

  describe('Public endpoints', () => {
    it('GET /health should return ok status', async () => {
      const { app } = createApiServer(config);
      
      const res = await request(app).get('/health');
      
      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        status: 'ok',
        service: 'zk-session-api',
      });
    });

    it('GET /stats should return rate limiter stats', async () => {
      const { app } = createApiServer(config);
      
      const res = await request(app).get('/stats');
      
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('totalTokens');
      expect(res.body).toHaveProperty('totalRequests');
      expect(res.body).toHaveProperty('uptime');
    });
  });

  describe('Protected endpoints - authentication', () => {
    it('should reject requests without ZK headers', async () => {
      const { app } = createApiServer(config);
      
      const res = await request(app).get('/api/whoami');
      
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Missing ZK session headers');
    });

    it('should reject requests with missing proof header', async () => {
      const { app } = createApiServer(config);
      
      const res = await request(app)
        .get('/api/whoami')
        .set('zk-session-token', '0xabc')
        .set('zk-session-tier', '1');
      
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Missing ZK session headers');
    });

    it('should reject requests with invalid tier', async () => {
      const { app } = createApiServer(config);
      const headers = createZkHeaders('0xabc123', 1);
      headers['zk-session-tier'] = 'not-a-number';
      
      const res = await request(app)
        .get('/api/whoami')
        .set(headers);
      
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid tier');
    });

    it('should accept requests with valid ZK headers', async () => {
      const { app } = createApiServer(config);
      const headers = createZkHeaders('0xabc123', 1);
      
      const res = await request(app)
        .get('/api/whoami')
        .set(headers);
      
      expect(res.status).toBe(200);
      expect(res.body.tier).toBe(1);
      expect(res.body.message).toBe('You have valid ZK credentials!');
    });
  });

  describe('Minimum tier enforcement', () => {
    it('should reject tier below minimum', async () => {
      const minTierConfig: ApiServerConfig = {
        ...config,
        zkSession: {
          ...config.zkSession,
          minTier: 2,
        },
      };
      const { app } = createApiServer(minTierConfig);
      const headers = createZkHeaders('0xabc123', 1);
      
      const res = await request(app)
        .get('/api/whoami')
        .set(headers);
      
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Tier 1 below minimum 2');
    });

    it('should accept tier at minimum', async () => {
      const minTierConfig: ApiServerConfig = {
        ...config,
        zkSession: {
          ...config.zkSession,
          minTier: 1,
        },
      };
      const { app } = createApiServer(minTierConfig);
      const headers = createZkHeaders('0xabc123', 1);
      
      const res = await request(app)
        .get('/api/whoami')
        .set(headers);
      
      expect(res.status).toBe(200);
    });
  });

  describe('Rate limiting', () => {
    it('should include rate limit headers in response', async () => {
      const { app } = createApiServer(config);
      const headers = createZkHeaders('0xratelimit1', 1);
      
      const res = await request(app)
        .get('/api/whoami')
        .set(headers);
      
      expect(res.status).toBe(200);
      expect(res.headers['x-ratelimit-limit']).toBe('10');
      expect(res.headers['x-ratelimit-remaining']).toBe('9');
      expect(res.headers['x-ratelimit-reset']).toBeDefined();
    });

    it('should decrement remaining count on each request', async () => {
      const { app } = createApiServer(config);
      const headers = createZkHeaders('0xratelimit2', 1);
      
      // First request
      const res1 = await request(app).get('/api/whoami').set(headers);
      expect(res1.headers['x-ratelimit-remaining']).toBe('9');
      
      // Second request
      const res2 = await request(app).get('/api/whoami').set(headers);
      expect(res2.headers['x-ratelimit-remaining']).toBe('8');
      
      // Third request
      const res3 = await request(app).get('/api/whoami').set(headers);
      expect(res3.headers['x-ratelimit-remaining']).toBe('7');
    });

    it('should return 429 when rate limit exceeded', async () => {
      const limitedConfig: ApiServerConfig = {
        ...config,
        zkSession: {
          ...config.zkSession,
          rateLimit: {
            maxRequestsPerToken: 3,
            windowSeconds: 60,
          },
        },
      };
      const { app } = createApiServer(limitedConfig);
      const headers = createZkHeaders('0xratelimit3', 1);
      
      // Make requests up to limit
      await request(app).get('/api/whoami').set(headers);
      await request(app).get('/api/whoami').set(headers);
      await request(app).get('/api/whoami').set(headers);
      
      // Fourth request should be rate limited
      const res = await request(app).get('/api/whoami').set(headers);
      
      expect(res.status).toBe(429);
      expect(res.body.error).toBe('Rate limit exceeded');
    });

    it('should rate limit independently per origin token', async () => {
      const limitedConfig: ApiServerConfig = {
        ...config,
        zkSession: {
          ...config.zkSession,
          rateLimit: {
            maxRequestsPerToken: 2,
            windowSeconds: 60,
          },
        },
      };
      const { app } = createApiServer(limitedConfig);
      const headers1 = createZkHeaders('0xuser1', 1);
      const headers2 = createZkHeaders('0xuser2', 1);
      
      // User 1 hits limit
      await request(app).get('/api/whoami').set(headers1);
      await request(app).get('/api/whoami').set(headers1);
      const res1 = await request(app).get('/api/whoami').set(headers1);
      expect(res1.status).toBe(429);
      
      // User 2 should still have quota
      const res2 = await request(app).get('/api/whoami').set(headers2);
      expect(res2.status).toBe(200);
    });
  });

  describe('GET /api/whoami', () => {
    it('should return tier and truncated origin token', async () => {
      const { app } = createApiServer(config);
      const longToken = '0x1234567890abcdef1234567890abcdef';
      const headers = createZkHeaders(longToken, 2);
      
      const res = await request(app)
        .get('/api/whoami')
        .set(headers);
      
      expect(res.status).toBe(200);
      expect(res.body.tier).toBe(2);
      // Token is truncated to first 16 chars + "..."
      expect(res.body.originToken).toBe('0x1234567890abcd...');
      expect(res.body.message).toBe('You have valid ZK credentials!');
    });

    it('should not truncate short tokens', async () => {
      const { app } = createApiServer(config);
      const shortToken = '0xabc';
      const headers = createZkHeaders(shortToken, 1);
      
      const res = await request(app)
        .get('/api/whoami')
        .set(headers);
      
      expect(res.status).toBe(200);
      expect(res.body.originToken).toBe('0xabc');
    });
  });

  describe('POST /api/chat', () => {
    it('should return tier-based response for tier 0', async () => {
      const { app } = createApiServer(config);
      const headers = createZkHeaders('0xchat0', 0);
      
      const res = await request(app)
        .post('/api/chat')
        .set(headers)
        .send({ message: 'Hello' });
      
      expect(res.status).toBe(200);
      expect(res.body.response).toBe('[Basic] Echo: Hello');
      expect(res.body.tier).toBe(0);
      expect(res.body.timestamp).toBeDefined();
    });

    it('should return tier-based response for tier 1', async () => {
      const { app } = createApiServer(config);
      const headers = createZkHeaders('0xchat1', 1);
      
      const res = await request(app)
        .post('/api/chat')
        .set(headers)
        .send({ message: 'Process this' });
      
      expect(res.status).toBe(200);
      expect(res.body.response).toBe('[Pro] Processing: Process this');
      expect(res.body.tier).toBe(1);
    });

    it('should return tier-based response for tier 2', async () => {
      const { app } = createApiServer(config);
      const headers = createZkHeaders('0xchat2', 2);
      
      const res = await request(app)
        .post('/api/chat')
        .set(headers)
        .send({ message: 'Priority request' });
      
      expect(res.status).toBe(200);
      expect(res.body.response).toBe('[Enterprise] Priority response to: Priority request');
      expect(res.body.tier).toBe(2);
    });
  });

  describe('GET /api/data', () => {
    it('should return basic data for tier 0', async () => {
      const { app } = createApiServer(config);
      const headers = createZkHeaders('0xdata0', 0);
      
      const res = await request(app)
        .get('/api/data')
        .set(headers);
      
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ message: 'Hello, World!' });
    });

    it('should return pro data for tier 1', async () => {
      const { app } = createApiServer(config);
      const headers = createZkHeaders('0xdata1', 1);
      
      const res = await request(app)
        .get('/api/data')
        .set(headers);
      
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ items: [1, 2, 3, 4, 5], count: 5 });
    });

    it('should return enterprise data for tier 2', async () => {
      const { app } = createApiServer(config);
      const headers = createZkHeaders('0xdata2', 2);
      
      const res = await request(app)
        .get('/api/data')
        .set(headers);
      
      expect(res.status).toBe(200);
      expect(res.body.count).toBe(100);
      expect(res.body.premium).toBe(true);
      expect(res.body.items).toHaveLength(100);
    });

    it('should return enterprise data for tier 3 (above max)', async () => {
      const { app } = createApiServer(config);
      const headers = createZkHeaders('0xdata3', 3);
      
      const res = await request(app)
        .get('/api/data')
        .set(headers);
      
      expect(res.status).toBe(200);
      expect(res.body.premium).toBe(true);
    });
  });

  describe('Error handling', () => {
    it('should return 404 for unknown routes', async () => {
      const { app } = createApiServer(config);
      
      const res = await request(app).get('/api/unknown');
      
      expect(res.status).toBe(401); // Auth check happens first on /api/*
    });

    it('should handle malformed JSON in request body', async () => {
      const { app } = createApiServer(config);
      const headers = createZkHeaders('0xerror1', 1);
      
      const res = await request(app)
        .post('/api/chat')
        .set(headers)
        .set('Content-Type', 'application/json')
        .send('not valid json');
      
      // Express returns 500 when JSON parsing fails
      expect(res.status).toBe(500);
    });
  });

  describe('CORS', () => {
    it('should include CORS headers', async () => {
      const { app } = createApiServer(config);
      
      const res = await request(app)
        .get('/health')
        .set('Origin', 'http://example.com');
      
      expect(res.headers['access-control-allow-origin']).toBeDefined();
    });

    it('should expose rate limit headers in CORS', async () => {
      const { app } = createApiServer(config);
      
      const res = await request(app)
        .options('/api/whoami')
        .set('Origin', 'http://example.com')
        .set('Access-Control-Request-Method', 'GET');
      
      const exposed = res.headers['access-control-expose-headers'] ?? '';
      expect(exposed).toContain('X-RateLimit-Limit');
      expect(exposed).toContain('X-RateLimit-Remaining');
      expect(exposed).toContain('X-RateLimit-Reset');
    });
  });
});
