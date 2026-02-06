/**
 * API Server with ZK Credential Protection
 * 
 * Example server demonstrating ZK credential verification.
 */

import express, { type Request, type Response } from 'express';
import cors from 'cors';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { ZkCredentialMiddleware, type ZkCredentialConfig } from './middleware.js';
import { hexToBigInt } from '@demo/crypto';

export interface ApiServerConfig {
  port: number;
  zkCredential: ZkCredentialConfig;
  corsOrigins?: string[];
}

export function createApiServer(config: ApiServerConfig) {
  const app = express();
  const zkCredential = new ZkCredentialMiddleware(config.zkCredential);

  // Middleware
  app.use(cors({
    origin: config.corsOrigins ?? '*',
    exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
  }));
  app.use(express.json({ limit: '64kb' }));

  // Health check (public)
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'zk-credential-api' });
  });

  // Stats (public)
  app.get('/stats', (_req, res) => {
    res.json({
      ...zkCredential.getStats(),
      uptime: process.uptime(),
    });
  });

  // Protected routes
  const protectedRouter = express.Router();
  protectedRouter.use(zkCredential.middleware());

  // Example protected endpoint
  protectedRouter.all('/whoami', (req: Request, res: Response) => {
    const token = req.zkCredential?.originToken ?? '';
    const truncatedToken = token.length > 16 ? `${token.slice(0, 16)}...` : token;

    res.json({
      tier: req.zkCredential?.tier,
      originToken: truncatedToken,
      message: 'You have valid ZK credentials!',
    });
  });

  // Chat endpoint (simulates AI API)
  protectedRouter.all('/chat', (req: Request, res: Response) => {
    const { message } = req.body;

    // Tier-based response
    const tier = req.zkCredential?.tier ?? 0;
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
  protectedRouter.all('/data', (req: Request, res: Response) => {
    const tier = req.zkCredential?.tier ?? 0;

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
    const isJsonParseError = err instanceof SyntaxError && 'body' in err;
    const status = isJsonParseError ? 400 : 500;
    const message = isJsonParseError ? 'Invalid JSON' : err.message;

    console.error('[API] Error:', message);

    // Don't send response if headers already sent (prevents crash on streaming errors)
    if (res.headersSent) {
      return;
    }

    res.status(status).json({ error: message });
  });

  let httpServer: http.Server | null = null;

  return {
    app,
    start: () => {
      return new Promise<void>((resolve) => {
        // Use http.createServer to allow larger headers for UltraHonk proofs (~16-20KB)
        httpServer = http.createServer({ maxHeaderSize: 65536 }, app);
        httpServer.listen(config.port, () => {
          console.log(`[API] Server running on port ${config.port}`);
          console.log(`[API] Service ID: ${config.zkCredential.serviceId}`);
          console.log(`[API] Rate limit: ${config.zkCredential.rateLimit.maxRequestsPerToken} requests per ${config.zkCredential.rateLimit.windowSeconds}s`);
          resolve();
        });
      });
    },
    stop: () => {
      return new Promise<void>((resolve, reject) => {
        if (!httpServer) {
          resolve();
          return;
        }
        httpServer.close((err) => {
          if (err) reject(err);
          else resolve();
        });
        httpServer = null;
      });
    },
  };
}

// Run as standalone server
const thisFile = fileURLToPath(import.meta.url);
const mainArg = path.resolve(process.argv[1]);
const isMain = thisFile === mainArg;
if (isMain) {
  const skipProofVerification = process.env.SKIP_PROOF_VERIFICATION === 'true'; // Default to false (real verification)

  // Facilitator public key is required in production mode (spec §4, §6)
  const facilitatorPubkeyX = process.env.FACILITATOR_PUBKEY_X;
  const facilitatorPubkeyY = process.env.FACILITATOR_PUBKEY_Y;

  if (!skipProofVerification && (!facilitatorPubkeyX || !facilitatorPubkeyY)) {
    console.error('[API] Error: FACILITATOR_PUBKEY_X and FACILITATOR_PUBKEY_Y are required when proof verification is enabled.');
    console.error('[API] Set SKIP_PROOF_VERIFICATION=true for development without real keys.');
    process.exit(1);
  }

  // Use dummy keys in skip mode (they won't be used for verification)
  // Use valid BN254/Grumpkin point for dummy keys to avoid Noir crashes
  // Point: (1, 17631683881184975370165255887551781615748384631227002551410204835505589172088)
  // This is a valid Grumpkin point (x=1)
  const pubkeyX = facilitatorPubkeyX ?? '0x0c24bf5f0365fe0876b48a7b1a4c6941d20aa8c59963b48fa2c937fcdd5ec836';
  const pubkeyY = facilitatorPubkeyY ?? '0x1b5fa4c18138ad44ec555b48cd85155693b446f96e5a9a3a46076666946ba192';

  if (skipProofVerification && (!facilitatorPubkeyX || !facilitatorPubkeyY)) {
    console.warn('[API] Warning: Using dummy facilitator public keys (proof verification is disabled)')
  }

  const config: ApiServerConfig = {
    port: parseInt(process.env.PORT ?? '3002'),
    zkCredential: {
      serviceId: BigInt(process.env.SERVICE_ID ?? '1'),
      facilitatorPubkey: {
        x: hexToBigInt(pubkeyX),
        y: hexToBigInt(pubkeyY),
      },
      rateLimit: {
        maxRequestsPerToken: parseInt(process.env.RATE_LIMIT_MAX ?? '100'),
        windowSeconds: parseInt(process.env.RATE_LIMIT_WINDOW ?? '60'),
      },
      minTier: parseInt(process.env.MIN_TIER ?? '0'),
      skipProofVerification,
      facilitatorUrl: process.env.FACILITATOR_URL ?? 'http://localhost:3001/settle',
      paymentAmount: process.env.PAYMENT_AMOUNT ?? '100000',  // 0.10 USDC in 6 decimals
      paymentAsset: process.env.PAYMENT_ASSET ?? 'USDC',
      paymentRecipient: process.env.PAYMENT_RECIPIENT ?? '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', // Default to Anvil Account 0 (Facilitator)
    },
  };

  const server = createApiServer(config);
  server.start();
}
