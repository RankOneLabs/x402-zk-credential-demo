/**
 * ZK Session Verification Middleware
 * 
 * Verifies ZK proofs and enforces rate limits.
 * Compliant with x402 zk-session spec v0.1.0
 * 
 * **Security Note (Replay Protection):**
 * Proofs are valid within a time window (60s past, 5s future) and could
 * theoretically be replayed within that window. However, replays use the
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
  addSchemePrefix,
  type Point,
  type X402WithZKSessionResponse,
  type ZKSessionError,
  type ZKSessionErrorCode,
  ERROR_CODE_TO_STATUS,
} from '@demo/crypto';
import { RateLimiter, type RateLimitConfig } from './ratelimit.js';
import { ZkVerifier, parseProofFromRequest } from './verifier.js';

/**
 * Structured error types for payment processing
 */
type PaymentErrorCode = 
  | 'INVALID_PAYMENT_SIGNATURE'
  | 'INVALID_REQUEST_STRUCTURE'
  | 'PAYMENT_REJECTED'
  | 'FACILITATOR_UNAVAILABLE'
  | 'FACILITATOR_ERROR'
  | 'PAYMENT_PROCESSING_ERROR';

class PaymentError extends Error {
  constructor(
    public readonly code: PaymentErrorCode,
    public readonly httpStatus: number,
    message: string
  ) {
    super(message);
    this.name = 'PaymentError';
  }
}

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
  /** Facilitator URL for settlement (spec §6) */
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

/** Discriminated union for session verification results */
export type SessionVerificationResult =
  | { valid: true; tier: number; originToken: string }
  | { valid: false; errorCode: ZKSessionErrorCode; message?: string };

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
  private pruneIntervalId: NodeJS.Timeout | null = null;

  constructor(private readonly config: ZkSessionConfig) {
    this.rateLimiter = new RateLimiter(config.rateLimit);
    this.verifier = new ZkVerifier({
      skipVerification: config.skipProofVerification,
    });

    // Prune expired entries every minute
    this.pruneIntervalId = setInterval(() => {
      const pruned = this.rateLimiter.prune();
      if (pruned > 0) {
        console.log(`[ZkSession] Pruned ${pruned} expired rate limit entries`);
      }
    }, 60000);

    // Prevent interval from keeping process alive
    this.pruneIntervalId.unref();
  }

  /**
   * Get scheme-prefixed public key for 402 response
   */
  private getFacilitatorPubkeyPrefixed(): string {
    const xHex = this.config.issuerPubkey.x.toString(16).padStart(64, '0');
    const yHex = this.config.issuerPubkey.y.toString(16).padStart(64, '0');
    return addSchemePrefix('pedersen-schnorr-bn254', `0x04${xHex}${yHex}`);
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
   * Build x402 Payment Required response (spec §6)
   * Uses @x402/core PaymentRequired format with accepts[] array
   */
  private build402Response(resourceUrl: string): X402WithZKSessionResponse {
    const paymentReqs = this.buildPaymentRequirements();
    
    return {
      x402Version: 2,
      resource: {
        url: resourceUrl,
        description: this.config.resourceDescription ?? 'ZK Session protected resource',
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
        zk_session: {
          version: '0.1',
          schemes: ['pedersen-schnorr-bn254'],
          facilitator_pubkey: this.getFacilitatorPubkeyPrefixed(),
          facilitator_url: this.config.facilitatorUrl,
        },
      },
    };
  }

  /**
   * Build ZK session error response (spec §13)
   */
  private buildErrorResponse(code: ZKSessionErrorCode, message?: string): ZKSessionError {
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
   * Express middleware for ZK session verification (spec §11)
   */
  middleware() {
    return async (req: Request, res: Response, next: NextFunction) => {
      // 0. Handle Payment Settlement (Mediated Flow)
      const paymentSig = req.get('PAYMENT-SIGNATURE');
      if (paymentSig) {
        try {
          console.log('[ZkSession] Processing payment signature...');
          
          let payload: Record<string, unknown>;
          try {
            const payloadStr = Buffer.from(paymentSig, 'base64').toString('utf-8');
            payload = JSON.parse(payloadStr);
          } catch {
            throw new PaymentError(
              'INVALID_PAYMENT_SIGNATURE',
              400,
              'Malformed payment signature: unable to parse'
            );
          }

          // Validate zk_session location per spec §7.2
          // Only accept extensions.zk_session - reject ambiguous structures
          if (payload.zk_session && (payload as { extensions?: { zk_session?: unknown } }).extensions?.zk_session) {
            throw new PaymentError(
              'INVALID_REQUEST_STRUCTURE',
              400,
              'Ambiguous request: zk_session found in both root and extensions'
            );
          }
          const zkSessionData = (payload as { extensions?: { zk_session?: { commitment?: string } } }).extensions?.zk_session;
          if (!zkSessionData?.commitment) {
            throw new PaymentError(
              'INVALID_REQUEST_STRUCTURE',
              400,
              'Missing extensions.zk_session.commitment per spec §7.2'
            );
          }

          // Call Facilitator /settle
          // Reuse buildPaymentRequirements() to ensure consistency with 402 response
          const settleReq = {
            payment: payload.payment,
            paymentRequirements: this.buildPaymentRequirements(),
            zk_session: zkSessionData,
          };

          let settleResp: globalThis.Response;
          try {
            settleResp = await fetch(this.config.facilitatorUrl, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(settleReq),
            });
          } catch (fetchError) {
            throw new PaymentError(
              'FACILITATOR_UNAVAILABLE',
              503,
              'Payment facilitator is temporarily unavailable. Please retry.'
            );
          }

          if (!settleResp.ok) {
            const errBody = await settleResp.text();
            if (settleResp.status >= 400 && settleResp.status < 500) {
              throw new PaymentError(
                'PAYMENT_REJECTED',
                402,
                `Payment rejected by facilitator: ${errBody}`
              );
            } else {
              throw new PaymentError(
                'FACILITATOR_UNAVAILABLE',
                503,
                'Payment facilitator is temporarily unavailable. Please retry.'
              );
            }
          }

          const settleData: unknown = await settleResp.json();

          // Validate settlement response structure (SettlementResponse from facilitator/types.ts)
          if (!settleData || typeof settleData !== 'object') {
            throw new PaymentError(
              'FACILITATOR_ERROR',
              502,
              'Payment facilitator returned an invalid response'
            );
          }

          const response = settleData as Record<string, unknown>;

          // Validate payment_receipt
          if (!response.payment_receipt || typeof response.payment_receipt !== 'object') {
            throw new PaymentError(
              'FACILITATOR_ERROR',
              502,
              'Settlement response missing payment_receipt'
            );
          }
          const receipt = response.payment_receipt as Record<string, unknown>;
          if (receipt.status !== 'settled') {
            throw new PaymentError(
              'PAYMENT_REJECTED',
              402,
              `Settlement failed: status=${receipt.status}`
            );
          }

          // Validate zk_session.credential
          if (!response.zk_session || typeof response.zk_session !== 'object') {
            throw new PaymentError(
              'FACILITATOR_ERROR',
              502,
              'Settlement response missing zk_session'
            );
          }
          const zkSession = response.zk_session as Record<string, unknown>;
          if (!zkSession.credential || typeof zkSession.credential !== 'object') {
            throw new PaymentError(
              'FACILITATOR_ERROR',
              502,
              'Settlement response missing zk_session.credential'
            );
          }
          const cred = zkSession.credential as Record<string, unknown>;

          // Validate required credential fields
          if (typeof cred.tier !== 'number') {
            throw new PaymentError(
              'FACILITATOR_ERROR',
              502,
              'Settlement response credential missing tier'
            );
          }

          // Construct X402PaymentResponse
          const clientResp = {
            x402Version: 2,
            payment_receipt: {
              status: 'settled',
              txHash: receipt.txHash,
              amountUSDC: receipt.amountUSDC,
            },
            zk_session: {
              credential: cred,
            },
          };

          res.set('PAYMENT-RESPONSE', Buffer.from(JSON.stringify(clientResp)).toString('base64'));

          // Grant access for this request
          req.zkSession = {
            tier: cred.tier as number,
            originToken: 'payment-session', // Placeholder for payment-based session
          };

          console.log('[ZkSession] Payment settled, credential issued. Granting access.');
          next();
          return;

        } catch (error) {
          console.error('[ZkSession] Payment processing failed:', error instanceof Error ? error.message : String(error));

          if (error instanceof PaymentError) {
            res.status(error.httpStatus).json({
              error: error.code,
              message: error.message,
            });
            return;
          }

          // Unknown error - return 500 to avoid silent failures
          res.status(500).json({
            error: 'PAYMENT_PROCESSING_ERROR',
            message: 'An unexpected error occurred processing payment',
          });
          return;
        }
      }

      const result = await this.verifyRequest(req);

      if (!result.valid) {
        // 402: Payment Required when no credentials provided (spec §6)
        // Prompts client to discover payment requirements and obtain credentials
        if (!req.headers.authorization) {
          const resourceUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
          res.status(402).json(this.build402Response(resourceUrl));
          return;
        }

        const status = ERROR_CODE_TO_STATUS[result.errorCode];

        // 401: Add WWW-Authenticate header (spec §13)
        if (status === 401) {
          res.set('WWW-Authenticate', 'ZKSession schemes="pedersen-schnorr-bn254"');
        }

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

      // Attach session info to request
      req.zkSession = {
        tier: result.tier,
        originToken: result.originToken,
      };

      next();
    };
  }

  /**
   * Parse Authorization header (spec §8.1)
   * Format: Authorization: ZKSession <scheme>:<base64-proof>
   */
  private parseAuthorizationHeader(req: Request): { scheme: string; proofB64: string } | null {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return null;
    }

    // Check for ZKSession prefix
    if (!authHeader.startsWith('ZKSession ')) {
      return null;
    }

    const payload = authHeader.slice('ZKSession '.length);
    const colonIdx = payload.indexOf(':');
    if (colonIdx === -1) {
      return null;
    }

    const scheme = payload.slice(0, colonIdx);
    const proofB64 = payload.slice(colonIdx + 1);

    return { scheme, proofB64 };
  }

  /**
   * Verify a request's ZK session (spec §11)
   * 
   * Verification flow:
   * 1. Parse Authorization header for ZKSession scheme
   * 2. If missing → return error (middleware will return 402)
   * 3. Extract scheme prefix from proof
   * 4. If unsupported scheme → 400 unsupported_zk_scheme
   * 5. Construct public inputs: (service_id, current_time, origin_id, facilitator_pubkey)
   * 6. Verify proof
   * 7. If invalid → 401 invalid_zk_proof
   * 8. Extract outputs: (origin_token, tier)
   * 9. Check tier meets endpoint requirement
   * 10. If insufficient → 403 tier_insufficient
   * 11. Return success (rate limiting handled by middleware)
   */
  async verifyRequest(req: Request): Promise<SessionVerificationResult> {
    // Step 1-2: Parse Authorization header
    const authData = this.parseAuthorizationHeader(req);
    if (!authData) {
      // No authorization - will trigger 402 response
      return { valid: false, errorCode: 'invalid_zk_proof', message: 'Missing Authorization header' };
    }

    // Step 3-4: Check scheme
    if (authData.scheme !== 'pedersen-schnorr-bn254') {
      return { valid: false, errorCode: 'unsupported_zk_scheme', message: `Unsupported scheme: ${authData.scheme}` };
    }

    // Parse the proof from base64
    const proofData = parseProofFromRequest(authData.proofB64);
    if (!proofData) {
      return { valid: false, errorCode: 'invalid_zk_proof', message: 'Invalid proof format' };
    }

    // Skip proof verification in development mode
    if (this.config.skipProofVerification) {
      console.log(`[ZkSession] Skipping proof verification (dev mode)`);
      // In dev mode, extract tier and originToken from publicInputs (outputs are at indices 5,6)
      // Layout: [service_id, current_time, origin_id, issuer_pubkey_x, issuer_pubkey_y, origin_token, tier]
      const tier = proofData.publicInputs[6] ? Number(BigInt(proofData.publicInputs[6])) : 0;
      const originToken = proofData.publicInputs[5] ?? '0x0';

      // Still check minimum tier requirement even in skip mode
      if (tier < (this.config.minTier ?? 0)) {
        return { valid: false, errorCode: 'tier_insufficient', message: `Tier ${tier} below minimum ${this.config.minTier}` };
      }

      return { valid: true, tier, originToken };
    }

    // Step 5: Compute expected origin_id for this endpoint
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
        // Allow asymmetric time drift for current_time:
        // - Past: up to 60s (network latency, processing time)
        // - Future: up to 5s (clock skew only, prevents pre-generation)
        if (i === 1) {
          const proofTime = BigInt(proofData.publicInputs[i] ?? '0x0');
          const isPast = proofTime < currentTime;
          const drift = isPast
            ? currentTime - proofTime
            : proofTime - currentTime;
          const maxDrift = isPast ? 60n : 5n;
          if (drift <= maxDrift) {
            continue; // Accept with allowed time drift
          }
          // Time check failure could indicate expired proof - check if too old
          if (isPast && drift > 60n) {
            return { valid: false, errorCode: 'proof_expired', message: 'Proof timestamp too old' };
          }
        }
        return {
          valid: false,
          errorCode: 'invalid_zk_proof',
          message: `Public input mismatch at index ${i}`
        };
      }
    }

    // Step 6-7: Verify the ZK proof
    try {
      const result = await this.verifier.verify(proofData);

      if (!result.valid) {
        return { valid: false, errorCode: 'invalid_zk_proof', message: result.error ?? 'Proof verification failed' };
      }

      // Step 8: Extract outputs (origin_token, tier)
      const originToken = result.outputs?.originToken ?? '';
      const tier = result.outputs?.tier ?? 0;

      // Step 10-11: Check minimum tier requirement
      if (tier < (this.config.minTier ?? 0)) {
        return { valid: false, errorCode: 'tier_insufficient', message: `Tier ${tier} below minimum ${this.config.minTier}` };
      }

      console.log(`[ZkSession] Proof verified for tier ${tier}, origin: ${originId.toString(16).slice(0, 16)}...`);

      return { valid: true, tier, originToken };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { valid: false, errorCode: 'invalid_zk_proof', message: `Proof verification failed: ${message}` };
    }
  }

  /**
   * Compute origin_id for a request
   * Recommended normalization: poseidon(METHOD, path_without_query, host)
   * For simplicity in demo: hash of pathname only (strips query params)
   */
  private computeOriginId(req: Request): bigint {
    // Use originalUrl to get the full path (req.url is stripped in mounted routers)
    const url = new URL(req.originalUrl, `http://${req.headers.host}`);
    // Normalize: strip query params, strip trailing slashes, lowercase
    let pathname = url.pathname.toLowerCase();
    if (pathname.endsWith('/') && pathname.length > 1) {
      pathname = pathname.slice(0, -1);
    }
    return stringToField(pathname);
  }

  /**
   * Get rate limiter stats
   */
  getStats() {
    return this.rateLimiter.stats();
  }
}
