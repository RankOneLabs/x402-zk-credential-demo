/**
 * Issuer Express Server
 * 
 * HTTP server that issues credentials via REST API.
 */

import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CredentialIssuer, type IssuerConfig } from './issuer.js';
import type { IssuanceRequest } from './types.js';

export interface IssuerServerConfig extends IssuerConfig {
  port: number;
  corsOrigins?: string[];
}

export function createIssuerServer(config: IssuerServerConfig) {
  const app = express();
  const issuer = new CredentialIssuer(config);
  
  // Middleware
  app.use(cors({
    origin: config.corsOrigins ?? '*',
  }));
  app.use(express.json());
  
  // Health check
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'zk-session-issuer' });
  });
  
  // Get issuer info (public key, tiers)
  app.get('/info', (_req, res) => {
    const pubkey = issuer.getPublicKey();
    res.json({
      serviceId: config.serviceId.toString(),
      issuerPubkey: {
        x: '0x' + pubkey.x.toString(16),
        y: '0x' + pubkey.y.toString(16),
      },
      tiers: config.tiers.map(t => ({
        tier: t.tier,
        priceUSDC: t.minAmountCents / 100,
        maxPresentations: t.maxPresentations,
        durationSeconds: t.durationSeconds,
      })),
    });
  });
  
  // Issue credential
  app.post('/credentials/issue', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const request = req.body as IssuanceRequest;
      
      // Validate request
      if (!request.userCommitment?.x || !request.userCommitment?.y) {
        res.status(400).json({ error: 'Missing userCommitment' });
        return;
      }
      
      if (!request.paymentProof) {
        res.status(400).json({ error: 'Missing paymentProof' });
        return;
      }
      
      const response = await issuer.issueCredential(request);
      res.json(response);
    } catch (error) {
      next(error);
    }
  });
  
  // Error handler
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error('[Issuer] Error:', err.message);
    res.status(500).json({ error: err.message });
  });
  
  return {
    app,
    start: () => {
      return new Promise<void>((resolve) => {
        app.listen(config.port, () => {
          console.log(`[Issuer] Server running on port ${config.port}`);
          console.log(`[Issuer] Service ID: ${config.serviceId}`);
          console.log(`[Issuer] Mock payments: ${config.allowMockPayments ? 'enabled' : 'disabled'}`);
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
  // Parse chain configuration
  const chainId = parseInt(process.env.CHAIN_ID ?? '84532'); // Default to Base Sepolia
  const recipientAddress = process.env.RECIPIENT_ADDRESS as `0x${string}` | undefined;
  const rpcUrl = process.env.RPC_URL;
  
  // Default configuration for demo
  const config: IssuerServerConfig = {
    port: parseInt(process.env.PORT ?? '3001'),
    serviceId: BigInt(process.env.SERVICE_ID ?? '1'),
    secretKey: BigInt(process.env.ISSUER_SECRET_KEY ?? '0x1234567890abcdef'),
    allowMockPayments: process.env.ALLOW_MOCK_PAYMENTS === 'true',
    tiers: [
      { minAmountCents: 1000, tier: 2, maxPresentations: 10000, durationSeconds: 30 * 24 * 60 * 60 }, // $10 = Enterprise
      { minAmountCents: 100, tier: 1, maxPresentations: 1000, durationSeconds: 7 * 24 * 60 * 60 },   // $1 = Pro
      { minAmountCents: 10, tier: 0, maxPresentations: 100, durationSeconds: 24 * 60 * 60 },         // $0.10 = Basic
    ],
    // On-chain verification (enabled if RECIPIENT_ADDRESS is set)
    ...(recipientAddress && {
      paymentVerification: {
        chainId,
        recipientAddress,
        rpcUrl,
      },
    }),
  };
  
  const server = createIssuerServer(config);
  server.start();
}
