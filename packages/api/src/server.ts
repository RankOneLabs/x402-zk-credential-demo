/**
 * API Server with ZK Session Protection
 * 
 * Example server demonstrating ZK session verification.
 */

import express, { type Request, type Response } from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ZkSessionMiddleware, type ZkSessionConfig } from './middleware.js';
import { hexToBigInt } from '@demo/crypto';

export interface ApiServerConfig {
  port: number;
  zkSession: ZkSessionConfig;
  corsOrigins?: string[];
}

export function createApiServer(config: ApiServerConfig) {
  const app = express();
  const zkSession = new ZkSessionMiddleware(config.zkSession);

  // Middleware
  app.use(cors({
    origin: config.corsOrigins ?? '*',
    exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
  }));
  app.use(express.json());

  // Health check (public)
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'zk-session-api' });
  });

  // Stats (public)
  app.get('/stats', (_req, res) => {
    res.json({
      ...zkSession.getStats(),
      uptime: process.uptime(),
    });
  });

  // Protected routes
  const protectedRouter = express.Router();
  protectedRouter.use(zkSession.middleware());

  // Example protected endpoint
  protectedRouter.get('/whoami', (req: Request, res: Response) => {
    const token = req.zkSession?.originToken ?? '';
    const truncatedToken = token.length > 16 ? `${token.slice(0, 16)}...` : token;

    res.json({
      tier: req.zkSession?.tier,
      originToken: truncatedToken,
      message: 'You have valid ZK credentials!',
    });
  });

  // Chat endpoint (simulates AI API)
  protectedRouter.post('/chat', (req: Request, res: Response) => {
    const { message } = req.body;

    // Tier-based response
    const tier = req.zkSession?.tier ?? 0;
    const responses: Record<number, string> = {
      0: `[Basic] Echo: ${message}`,
      1: `[Pro] Processing: ${message}`,
      2: `[Enterprise] Priority response to: ${message}`,
    };

    res.json({
      response: responses[tier] ?? responses[0],
      tier,
      timestamp: Date.now(),
    });
  });

  // Data endpoint
  protectedRouter.get('/data', (req: Request, res: Response) => {
    const tier = req.zkSession?.tier ?? 0;

    // Return more data for higher tiers
    const data = {
      basic: { message: 'Hello, World!' },
      pro: { items: [1, 2, 3, 4, 5], count: 5 },
      enterprise: { items: Array.from({ length: 100 }, (_, i) => i), count: 100, premium: true },
    };

    if (tier >= 2) {
      res.json(data.enterprise);
    } else if (tier >= 1) {
      res.json(data.pro);
    } else {
      res.json(data.basic);
    }
  });

  app.use('/api', protectedRouter);

  // Error handler
  app.use((err: Error, _req: Request, res: Response, _next: express.NextFunction) => {
    console.error('[API] Error:', err.message);

    // Don't send response if headers already sent (prevents crash on streaming errors)
    if (res.headersSent) {
      return;
    }

    res.status(500).json({ error: err.message });
  });

  return {
    app,
    start: () => {
      return new Promise<void>((resolve) => {
        app.listen(config.port, () => {
          console.log(`[API] Server running on port ${config.port}`);
          console.log(`[API] Service ID: ${config.zkSession.serviceId}`);
          console.log(`[API] Rate limit: ${config.zkSession.rateLimit.maxRequestsPerToken} requests per ${config.zkSession.rateLimit.windowSeconds}s`);
          resolve();
        });
      });
    },
  };
}

// Run as standalone server
const thisFile = fileURLToPath(import.meta.url);
const mainArg = path.resolve(process.argv[1]);
const isMain = thisFile === mainArg;
if (isMain) {
  const skipProofVerification = process.env.SKIP_PROOF_VERIFICATION === 'true';

  // Issuer public key is required in production mode
  const issuerPubkeyX = process.env.ISSUER_PUBKEY_X;
  const issuerPubkeyY = process.env.ISSUER_PUBKEY_Y;

  if (!skipProofVerification && (!issuerPubkeyX || !issuerPubkeyY)) {
    console.error('[API] Error: ISSUER_PUBKEY_X and ISSUER_PUBKEY_Y are required when proof verification is enabled.');
    console.error('[API] Set SKIP_PROOF_VERIFICATION=true for development without real keys.');
    process.exit(1);
  }

  // Use dummy keys in skip mode (they won't be used for verification)
  const pubkeyX = issuerPubkeyX ?? '0x1';
  const pubkeyY = issuerPubkeyY ?? '0x2';

  if (skipProofVerification && (!issuerPubkeyX || !issuerPubkeyY)) {
    console.warn('[API] Warning: Using dummy issuer public keys (proof verification is disabled)');
  }

  const config: ApiServerConfig = {
    port: parseInt(process.env.PORT ?? '3002'),
    zkSession: {
      serviceId: BigInt(process.env.SERVICE_ID ?? '1'),
      issuerPubkey: {
        x: hexToBigInt(pubkeyX),
        y: hexToBigInt(pubkeyY),
      },
      rateLimit: {
        maxRequestsPerToken: parseInt(process.env.RATE_LIMIT_MAX ?? '100'),
        windowSeconds: parseInt(process.env.RATE_LIMIT_WINDOW ?? '60'),
      },
      minTier: parseInt(process.env.MIN_TIER ?? '0'),
      skipProofVerification,
    },
  };

  const server = createApiServer(config);
  server.start();
}
