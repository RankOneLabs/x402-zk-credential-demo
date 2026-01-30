/**
 * ZK Session Verification Middleware
 * 
 * Verifies ZK proofs and enforces rate limits.
 */

import type { Request, Response, NextFunction } from 'express';
import { stringToField, bigIntToHex, type Point } from '@zk-session/crypto';
import { RateLimiter, type RateLimitConfig } from './ratelimit.js';
import { ZkVerifier, parseProofFromRequest } from './verifier.js';

export interface ZkSessionConfig {
  /** Service ID this server accepts credentials for */
  serviceId: bigint;
  /** Issuer's public key */
  issuerPubkey: Point;
  /** Rate limiting configuration */
  rateLimit: RateLimitConfig;
  /** Minimum tier required (default: 0) */
  minTier?: number;
  /** Skip proof verification (for development) */
  skipProofVerification?: boolean;
}

export interface VerificationResult {
  valid: boolean;
  tier?: number;
  originToken?: string;
  error?: string;
}

// Extend Express Request to include ZK session info
declare global {
  namespace Express {
    interface Request {
      zkSession?: {
        tier: number;
        originToken: string;
      };
    }
  }
}

export class ZkSessionMiddleware {
  private rateLimiter: RateLimiter;
  private verifier: ZkVerifier;
  
  constructor(private readonly config: ZkSessionConfig) {
    this.rateLimiter = new RateLimiter(config.rateLimit);
    this.verifier = new ZkVerifier({
      skipVerification: config.skipProofVerification,
    });
    
    // Prune expired entries every minute
    setInterval(() => {
      const pruned = this.rateLimiter.prune();
      if (pruned > 0) {
        console.log(`[ZkSession] Pruned ${pruned} expired rate limit entries`);
      }
    }, 60000);
  }
  
  /**
   * Express middleware for ZK session verification
   */
  middleware() {
    return async (req: Request, res: Response, next: NextFunction) => {
      const result = await this.verifyRequest(req);
      
      if (!result.valid) {
        res.status(401).json({ error: result.error });
        return;
      }
      
      // Check rate limit
      const rateLimit = this.rateLimiter.check(result.originToken!);
      
      // Add rate limit headers
      res.set('X-RateLimit-Limit', this.config.rateLimit.maxRequestsPerToken.toString());
      res.set('X-RateLimit-Remaining', rateLimit.remaining.toString());
      res.set('X-RateLimit-Reset', rateLimit.resetAt.toString());
      
      if (!rateLimit.allowed) {
        res.status(429).json({ error: 'Rate limit exceeded' });
        return;
      }
      
      // Attach session info to request
      req.zkSession = {
        tier: result.tier!,
        originToken: result.originToken!,
      };
      
      next();
    };
  }
  
  /**
   * Verify a request's ZK session headers
   */
  async verifyRequest(req: Request): Promise<VerificationResult> {
    // Extract headers
    const proofB64 = req.headers['zk-session-proof'] as string | undefined;
    const originToken = req.headers['zk-session-token'] as string | undefined;
    const tierStr = req.headers['zk-session-tier'] as string | undefined;
    
    if (!proofB64 || !originToken || !tierStr) {
      return { valid: false, error: 'Missing ZK session headers' };
    }
    
    const tier = parseInt(tierStr, 10);
    if (isNaN(tier)) {
      return { valid: false, error: 'Invalid tier' };
    }
    
    // Check minimum tier
    if (tier < (this.config.minTier ?? 0)) {
      return { valid: false, error: `Tier ${tier} below minimum ${this.config.minTier}` };
    }
    
    // Skip proof verification in development mode
    if (this.config.skipProofVerification) {
      console.log(`[ZkSession] Skipping proof verification (dev mode)`);
      return { valid: true, tier, originToken };
    }
    
    // Parse the proof from base64
    const proofData = parseProofFromRequest(proofB64);
    if (!proofData) {
      return { valid: false, error: 'Invalid proof format' };
    }
    
    // Compute expected origin_id for this endpoint
    const originId = this.computeOriginId(req);
    const currentTime = BigInt(Math.floor(Date.now() / 1000));
    
    // Build expected public inputs
    // Order: service_id, current_time, origin_id, issuer_pubkey_x, issuer_pubkey_y
    const expectedPublicInputs = [
      bigIntToHex(this.config.serviceId),
      bigIntToHex(currentTime),
      bigIntToHex(originId),
      bigIntToHex(this.config.issuerPubkey.x),
      bigIntToHex(this.config.issuerPubkey.y),
    ];
    
    // Verify the public inputs match (first 5 elements)
    for (let i = 0; i < 5; i++) {
      if (proofData.publicInputs[i] !== expectedPublicInputs[i]) {
        // Allow some time drift for current_time (±60 seconds)
        if (i === 1) {
          const proofTime = BigInt(proofData.publicInputs[i] ?? '0x0');
          const drift = proofTime > currentTime 
            ? proofTime - currentTime 
            : currentTime - proofTime;
          if (drift <= 60n) {
            continue; // Accept with time drift
          }
        }
        return { 
          valid: false, 
          error: `Public input mismatch at index ${i}` 
        };
      }
    }
    
    // Verify the ZK proof
    try {
      const result = await this.verifier.verify(proofData);
      
      if (!result.valid) {
        return { valid: false, error: result.error ?? 'Proof verification failed' };
      }
      
      // Verify the origin_token from proof matches the header
      if (result.outputs?.originToken !== originToken) {
        return { valid: false, error: 'Origin token mismatch' };
      }
      
      // Verify the tier from proof matches the header
      if (result.outputs?.tier !== tier) {
        return { valid: false, error: 'Tier mismatch' };
      }
      
      console.log(`[ZkSession] Proof verified for tier ${tier}, origin: ${originId.toString(16).slice(0, 16)}...`);
      
      return { valid: true, tier, originToken };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { valid: false, error: `Proof verification failed: ${message}` };
    }
  }
  
  /**
   * Compute origin_id for a request (hash of pathname)
   */
  private computeOriginId(req: Request): bigint {
    // Use pathname as origin identifier
    const pathname = new URL(req.url, `http://${req.headers.host}`).pathname;
    return stringToField(pathname);
  }
  
  /**
   * Get rate limiter stats
   */
  getStats() {
    return this.rateLimiter.stats();
  }
}
