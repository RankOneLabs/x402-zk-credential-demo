/**
 * ZK Credential Verification Middleware
 * 
 * Verifies ZK proofs and enforces rate limits.
 * Compliant with x402 zk-credential spec v0.1.0
 * 
 * **Security Note (Replay Protection):**
 * Proofs are valid within a time window (±60s) and could theoretically be
 * replayed within that window. However, replays use the
 * same origin_token and thus consume the same rate limit quota - an attacker
 * replaying your proof uses YOUR rate limit, not theirs.
 * 
 * For production systems requiring stronger replay protection, consider:
 * - Tracking seen proof hashes within the time window (memory overhead)
 * - Adding a client-generated nonce to the circuit (requires circuit changes)
 * - Reducing time tolerance further (may cause clock sync issues)
 */

import type { Request, Response, NextFunction } from 'express';
import {
  stringToField,
  bigIntToHex,
  type Point,
  type X402WithZKCredentialResponse,
  type ZKCredentialErrorResponse,
  type ZKCredentialErrorCode,
  ERROR_CODE_TO_STATUS,
  fromBase64Url,
  toBase64Url,
  pointToBytes,
  bytesToPoint,
  fieldToBytes,
} from '@demo/crypto';
import { RateLimiter, type RateLimitConfig } from './ratelimit.js';
import { ZkVerifier } from './verifier.js';

export interface ZkCredentialConfig {
  /** Service ID this server accepts credentials for */
  serviceId: bigint;
  /** Issuer public key for verifying credentials */
  issuerPubkey: Point;
  /** Rate limiting configuration */
  rateLimit: RateLimitConfig;
  /** Minimum tier required (default: 0) */
  minTier?: number;
  /** Skip proof verification (for development) */
  skipProofVerification?: boolean;
  /** Facilitator URL for settlement */
  facilitatorUrl: string;
  /** Payment amount in smallest unit (e.g., "100000" for 0.10 USDC) */
  paymentAmount?: string;
  /** Payment asset address (e.g., USDC contract address) */
  paymentAsset?: string;
  /** Payment recipient address (payTo) */
  paymentRecipient?: string;
  /** Network in CAIP-2 format (e.g., "eip155:84532" for Base Sepolia) */
  network?: string;
  /** Resource description for 402 response */
  resourceDescription?: string;
}

/** Discriminated union for credential verification results */
export type CredentialVerificationResult =
  | { valid: true; tier: number; originToken: string }
  | { valid: false; errorCode: ZKCredentialErrorCode; message?: string };

// Extend Express Request to include ZK credential info
declare global {
  namespace Express {
    interface Request {
      zkCredential?: {
        tier: number;
        originToken: string;
      };
    }
  }
}

export class ZkCredentialMiddleware {
  private rateLimiter: RateLimiter;
  private verifier: ZkVerifier;
  private pruneIntervalId: NodeJS.Timeout | null = null;

  constructor(private readonly config: ZkCredentialConfig) {
    this.rateLimiter = new RateLimiter(config.rateLimit);
    this.verifier = new ZkVerifier({
      skipVerification: config.skipProofVerification,
    });

    // Prune expired entries every minute
    this.pruneIntervalId = setInterval(() => {
      const pruned = this.rateLimiter.prune();
      if (pruned > 0) {
        console.log(`[ZkCredential] Pruned ${pruned} expired rate limit entries`);
      }
    }, 60000);

    // Prevent interval from keeping process alive
    this.pruneIntervalId.unref();
  }

  /**
   * Get suite-prefixed public key for 402 response
   */
  private getIssuerPubkeyBase64(): string {
    const pubKeyBytes = pointToBytes(this.config.issuerPubkey);
    return toBase64Url(pubKeyBytes);
  }

  /**
   * Build payment requirements for both 402 responses and settlement requests.
   * This ensures consistency between what we advertise and what we accept.
   */
  private buildPaymentRequirements() {
    return {
      scheme: 'exact' as const,
      network: (this.config.network ?? 'eip155:84532') as `${string}:${string}`,
      asset: this.config.paymentAsset ?? '0x036CbD53842c5426634e7929541eC2318f3dCF7e', // Base Sepolia USDC
      amount: this.config.paymentAmount ?? '100000',
      payTo: this.config.paymentRecipient ?? this.config.facilitatorUrl,
      maxTimeoutSeconds: 300,
      extra: {
        // EIP-712 domain info for USDC (required by @x402/evm)
        name: 'USD Coin',
        version: '1',
      },
    };
  }

  /**
   * Build x402 Payment Required response (spec §7)
   * Uses @x402/core PaymentRequired format with accepts[] array
   */
  private build402Response(resourceUrl: string): X402WithZKCredentialResponse {
    const paymentReqs = this.buildPaymentRequirements();

    return {
      x402Version: 2,
      resource: {
        url: resourceUrl,
        description: this.config.resourceDescription ?? 'ZK Credential protected resource',
        mimeType: 'application/json',
      },
      accepts: [
        {
          ...paymentReqs,
          // For 402 response, extra should be empty (client adds EIP-712 info)
          extra: {},
        },
      ],
      extensions: {
        'zk-credential': {
          info: {
            version: '0.1.0',
            credential_suites: ['pedersen-schnorr-poseidon-ultrahonk'],
            issuer_suite: 'pedersen-schnorr-poseidon-ultrahonk',
            issuer_pubkey: this.getIssuerPubkeyBase64(),
            max_credential_ttl: 86400,
            service_id: toBase64Url(fieldToBytes(this.config.serviceId)),
          },
          schema: {
            $schema: 'https://json-schema.org/draft/2020-12/schema',
            type: 'object',
            properties: {
              commitment: {
                type: 'string',
                description: "Suite-typed commitment: '<suite>:<base64url(point)>'",
              },
            },
          },
        },
      },
    };
  }

  /**
   * Build ZK credential error response (spec §14)
   */
  private buildErrorResponse(code: ZKCredentialErrorCode, message?: string): ZKCredentialErrorResponse {
    return { error: code, message };
  }

  /**
   * Clean up resources (timers, verifier backend)
   */
  async destroy(): Promise<void> {
    if (this.pruneIntervalId) {
      clearInterval(this.pruneIntervalId);
      this.pruneIntervalId = null;
    }
    await this.verifier.destroy();
  }

  /**
   * Express middleware for ZK credential verification
   * 
   * Transport layer:
   * - Phase 2 (Presentation): proof in body envelope { x402_zk_credential, payload }
   */
  middleware() {
    return async (req: Request, res: Response, next: NextFunction) => {
      // Phase 2: Presentation — body envelope is canonical signal
      if (!this.hasZkCredentialEnvelope(req.body)) {
        const resourceUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
        res.status(402).json(this.build402Response(resourceUrl));
        return;
      }

      const result = await this.verifyRequest(req);

      if (!result.valid) {
        const status = ERROR_CODE_TO_STATUS[result.errorCode];
        res.status(status).json(this.buildErrorResponse(result.errorCode, result.message));
        return;
      }

      // Check rate limit
      const rateLimit = this.rateLimiter.check(result.originToken);

      // Add rate limit headers
      res.set('X-RateLimit-Limit', this.config.rateLimit.maxRequestsPerToken.toString());
      res.set('X-RateLimit-Remaining', rateLimit.remaining.toString());
      res.set('X-RateLimit-Reset', rateLimit.resetAt.toString());

      if (!rateLimit.allowed) {
        res.status(429).json(this.buildErrorResponse('rate_limited', 'Rate limit exceeded'));
        return;
      }

      // Unwrap payload from envelope into req.body for downstream handlers
      const envelope = req.body as Record<string, unknown> | undefined;
      if (envelope && typeof envelope === 'object' && 'payload' in envelope) {
        req.body = envelope.payload ?? {};
      }

      // Attach credential info to request
      req.zkCredential = {
        tier: result.tier,
        originToken: result.originToken,
      };

      next();
    };
  }

  private hasZkCredentialEnvelope(body: unknown): boolean {
    if (!body || typeof body !== 'object') {
      return false;
    }
    return 'x402_zk_credential' in (body as Record<string, unknown>);
  }

  /**
  * Parse ZK credential presentation envelope from request body.
  * Reads from body.x402_zk_credential.
   */
  private parseProofEnvelope(req: Request): {
    suite: string;
    issuerPubkey: string;
    proofB64: string;
    currentTime: number;
    publicOutputs: { originToken: string; tier: number };
  } | null {
    const body = req.body as Record<string, unknown> | undefined;
    const zkSession = (body as { x402_zk_credential?: Record<string, unknown> } | undefined)?.x402_zk_credential;
    if (!zkSession || typeof zkSession !== 'object') {
      return null;
    }

    const suite = zkSession.suite;
    const issuerPubkey = zkSession.issuer_pubkey;
    const proofB64 = zkSession.proof;
    const currentTime = zkSession.current_time;
    const publicOutputs = zkSession.public_outputs as Record<string, unknown> | undefined;

    if (typeof suite !== 'string' || typeof issuerPubkey !== 'string' || typeof proofB64 !== 'string' || !publicOutputs) {
      return null;
    }

    const originToken = publicOutputs.origin_token;
    const tier = publicOutputs.tier;

    if (typeof originToken !== 'string' || typeof tier !== 'number') {
      return null;
    }
    // current_time is required — the proof is bound to the exact value used during
    // generation, so the server cannot substitute its own clock
    if (typeof currentTime !== 'number') {
      return null;
    }

    // Validate numeric fields that will be converted to BigInt later.
    // We require finite, non-negative safe integers to avoid runtime BigInt errors.
    if (
      !Number.isFinite(tier) ||
      !Number.isSafeInteger(tier) ||
      tier < 0 ||
      !Number.isFinite(currentTime) ||
      !Number.isSafeInteger(currentTime) ||
      currentTime < 0
    ) {
      return null;
    }
    return {
      suite,
      issuerPubkey,
      proofB64,
      currentTime,
      publicOutputs: { originToken, tier },
    };
  }

  /**
   * Strictly validate a base64url string
   * Valid base64url: A-Z, a-z, 0-9, -, _
   * No padding allowed per spec.
   */
  private isValidBase64Url(str: string): boolean {
    // Empty string is not valid
    if (str.length === 0) {
      return false;
    }

    // Check if string contains only valid base64url characters
    const base64UrlRegex = /^[A-Za-z0-9\-_]+$/;
    if (!base64UrlRegex.test(str)) {
      return false;
    }

    return true;
  }

  /**
   * Verify a request's ZK credential (spec §15)
   * 
   * Verification flow:
   * 1. Parse request body for zk-credential
   * 2. If missing → credential_missing
   * 3. Check suite support
  * 4. Construct public inputs: (service_id, current_time, origin_id, issuer_pubkey)
   * 5. Verify proof
   * 6. Extract outputs: (origin_token, tier)
   * 7. Check tier meets endpoint requirement
   * 8. Return success (rate limiting handled by middleware)
   */
  async verifyRequest(req: Request): Promise<CredentialVerificationResult> {
    // Step 1-2: Parse request body
    const presentation = this.parseProofEnvelope(req);
    if (!presentation) {
      return { valid: false, errorCode: 'credential_missing', message: 'Missing zk-credential presentation' };
    }

    // Step 3: Check suite
    if (presentation.suite !== 'pedersen-schnorr-poseidon-ultrahonk') {
      return { valid: false, errorCode: 'unsupported_suite', message: `Unsupported suite: ${presentation.suite}` };
    }

    const issuerKey = this.decodeIssuerPubkey(presentation.issuerPubkey);
    if (!issuerKey) {
      return { valid: false, errorCode: 'invalid_proof', message: 'Invalid issuer_pubkey encoding' };
    }
    if (issuerKey.x !== this.config.issuerPubkey.x || issuerKey.y !== this.config.issuerPubkey.y) {
      return { valid: false, errorCode: 'invalid_proof', message: 'Unauthorized issuer_pubkey for service_id' };
    }

    // Step 3.5: Strictly validate base64url proof encoding
    if (!this.isValidBase64Url(presentation.proofB64)) {
      return { valid: false, errorCode: 'invalid_proof', message: 'Invalid proof encoding' };
    }

    const proofBytes = fromBase64Url(presentation.proofB64);

    const originId = this.computeOriginId(req);
    const serverTime = BigInt(Math.floor(Date.now() / 1000));
    // Use the current_time from the presentation (matches the proof)
    const proofTime = BigInt(presentation.currentTime);

    // Validate the proof's current_time is within acceptable drift (±60 seconds)
    const MAX_TIME_DRIFT = 60n;
    const timeDiff = serverTime > proofTime ? serverTime - proofTime : proofTime - serverTime;
    if (timeDiff > MAX_TIME_DRIFT) {
      return { valid: false, errorCode: 'invalid_proof', message: `Proof time drift too large: ${timeDiff}s` };
    }

    // Skip proof verification in development mode
    if (this.config.skipProofVerification) {
      console.log(`[ZkCredential] Skipping proof verification (dev mode)`);
      const { tier, originToken } = presentation.publicOutputs;

      // Still check minimum tier requirement even in skip mode
      if (tier < (this.config.minTier ?? 0)) {
        return { valid: false, errorCode: 'tier_insufficient', message: `Tier ${tier} below minimum ${this.config.minTier}` };
      }

      return { valid: true, tier, originToken };
    }

    const publicInputs = [
      bigIntToHex(this.config.serviceId),
      bigIntToHex(proofTime),
      bigIntToHex(originId),
      bigIntToHex(issuerKey.x),
      bigIntToHex(issuerKey.y),
      presentation.publicOutputs.originToken,
      bigIntToHex(BigInt(presentation.publicOutputs.tier)),
    ];

    const proofData = {
      proof: new Uint8Array(proofBytes),
      publicInputs,
    };

    // Step 6-7: Verify the ZK proof
    try {
      const result = await this.verifier.verify(proofData);

      if (!result.valid) {
        return { valid: false, errorCode: 'invalid_proof', message: result.error ?? 'Proof verification failed' };
      }

      // Step 8: Extract outputs (origin_token, tier)
      const originToken = result.outputs?.originToken ?? '';
      const tier = result.outputs?.tier ?? 0;

      // Step 10-11: Check minimum tier requirement
      if (tier < (this.config.minTier ?? 0)) {
        return { valid: false, errorCode: 'tier_insufficient', message: `Tier ${tier} below minimum ${this.config.minTier}` };
      }

      return { valid: true, tier, originToken };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { valid: false, errorCode: 'invalid_proof', message: `Proof verification failed: ${message}` };
    }
  }

  private decodeIssuerPubkey(issuerPubkeyB64: string): Point | null {
    try {
      const bytes = fromBase64Url(issuerPubkeyB64);
      return bytesToPoint(bytes);
    } catch {
      return null;
    }
  }

  /**
  * Compute origin_id for a request
  * Spec normalization: stringToField(canonical_origin)
  * - scheme/host lowercase
  * - include non-default port only
  * - path from URL parser (empty -> /)
  * - query/fragment excluded
   */
  private computeOriginId(req: Request): bigint {
    const url = new URL(req.originalUrl, `${req.protocol}://${req.get('host')}`);

    const scheme = url.protocol.replace(':', '').toLowerCase();
    const hostname = url.hostname.toLowerCase();
    const port = url.port;
    const defaultPort = scheme === 'https' ? '443' : scheme === 'http' ? '80' : '';
    const host = port && port !== defaultPort ? `${hostname}:${port}` : hostname;

    const pathname = url.pathname || '/';
    const canonicalOrigin = `${scheme}://${host}${pathname}`;
    return stringToField(canonicalOrigin);
  }

  /**
   * Get rate limiter stats
   */
  getStats() {
    return this.rateLimiter.stats();
  }
}
