/**
 * Facilitator Express Server
 * 
 * HTTP server that issues credentials via REST API.
 * Compliant with x402 zk-credential spec v0.2.0
 */

import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CredentialIssuer, type IssuerConfig } from './issuer.js';
import type { SettlementRequest } from './types.js';
import { parseSchemePrefix } from '@demo/crypto';

export interface FacilitatorServerConfig extends IssuerConfig {
  port: number;
  corsOrigins?: string[];
}

export function createFacilitatorServer(config: FacilitatorServerConfig) {
  const app = express();
  const facilitator = new CredentialIssuer(config);

  // Middleware
  app.use(cors({
    origin: config.corsOrigins ?? '*',
  }));
  app.use(express.json());

  // Health check
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'zk-credential-facilitator' });
  });

  // Get facilitator info (public key, tiers) - spec compliant format
  app.get('/info', async (_req, res) => {
    const pubkeyPrefixed = await facilitator.getPublicKeyPrefixed();
    res.json({
      service_id: config.serviceId.toString(),
      facilitator_pubkey: pubkeyPrefixed,
      credential_suites: ['pedersen-schnorr-poseidon-ultrahonk'],
      tiers: config.tiers.map(t => ({
        tier: t.tier,
        price_usdc: t.minAmountCents / 100,
        presentation_budget: t.maxPresentations,
        duration_seconds: t.durationSeconds,
      })),
    });
  });

  // Settlement endpoint (spec §8.3, §8.4)
  // x402 v2 format with signed payment payload
  app.post('/settle', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const request = req.body as SettlementRequest;

      // Validate request structure
      if (!request.extensions?.zk_credential?.commitment) {
        res.status(400).json({ error: 'Missing extensions.zk_credential.commitment' });
        return;
      }

      if (!request.payment) {
        res.status(400).json({ error: 'Missing payment (x402 v2 PaymentPayload)' });
        return;
      }

      if (!request.paymentRequirements) {
        res.status(400).json({ error: 'Missing paymentRequirements' });
        return;
      }

      // Validate scheme prefix
      try {
        const { scheme } = parseSchemePrefix(request.extensions.zk_credential.commitment);
        if (scheme !== 'pedersen-schnorr-poseidon-ultrahonk') {
          res.status(400).json({ error: 'unsupported_suite', message: `Unsupported suite: ${scheme}` });
          return;
        }
      } catch {
        res.status(400).json({ error: 'Invalid commitment format: expected suite-prefixed string' });
        return;
      }

      const response = await facilitator.settle(request);
      res.json(response);
    } catch (error) {
      next(error);
    }
  });

  // Error handler
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error('[Facilitator] Error:', err.message);
    res.status(500).json({ error: err.message });
  });

  let httpServer: ReturnType<typeof app.listen> | null = null;

  return {
    app,
    start: () => {
      return new Promise<void>((resolve, reject) => {
        facilitator.initialize()
          .then(() => {
            httpServer = app.listen(config.port, () => {
              console.log(`[Facilitator] Server running on port ${config.port}`);
              console.log(`[Facilitator] Service ID: ${config.serviceId}`);
              console.log(`[Facilitator] Mock payments: ${config.allowMockPayments ? 'enabled' : 'disabled'}`);
              resolve();
            });
          })
          .catch((err: Error) => {
            console.error('[Facilitator] Failed to initialize:', err.message);
            reject(err);
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
  // Parse chain configuration
  const chainId = parseInt(process.env.CHAIN_ID ?? '84532'); // Default to Base Sepolia
  const recipientAddress = process.env.RECIPIENT_ADDRESS as `0x${string}` | undefined;
  const rpcUrl = process.env.RPC_URL;

  // Default configuration for demo
  const config: FacilitatorServerConfig = {
    port: parseInt(process.env.PORT ?? '3001'),
    serviceId: BigInt(process.env.SERVICE_ID ?? '1'),
    secretKey: BigInt(process.env.FACILITATOR_SECRET_KEY ?? '0x1234567890abcdef'),
    allowMockPayments: process.env.ALLOW_MOCK_PAYMENTS === 'true',
    tiers: [
      { minAmountCents: 1000, tier: 2, maxPresentations: 10000, durationSeconds: 30 * 24 * 60 * 60 }, // $10 = Enterprise
      { minAmountCents: 100, tier: 1, maxPresentations: 1000, durationSeconds: 7 * 24 * 60 * 60 },   // $1 = Pro
      { minAmountCents: 10, tier: 0, maxPresentations: 100, durationSeconds: 24 * 60 * 60 },         // $0.10 = Basic
    ],
    // EVM payment configuration (if private key is set)
    ...(process.env.FACILITATOR_PRIVATE_KEY && {
      evmPayment: {
        chainId,
        rpcUrl: rpcUrl ?? 'http://127.0.0.1:8545',
        facilitatorPrivateKey: process.env.FACILITATOR_PRIVATE_KEY as `0x${string}`,
        usdcAddress: (process.env.USDC_ADDRESS ?? '0x036CbD53842c5426634e7929541eC2318f3dCF7e') as `0x${string}`, // Base Sepolia Default
      },
    }),
  };

  const server = createFacilitatorServer(config);
  server.start();
}
