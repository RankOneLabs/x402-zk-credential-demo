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
  addSchemePrefix,
  poseidonHash3,
  type Point,
  type X402WithZKCredentialResponse,
  type ZKCredentialErrorResponse,
  type ZKCredentialErrorCode,
  ERROR_CODE_TO_STATUS,
} from '@demo/crypto';
import { RateLimiter, type RateLimitConfig } from './ratelimit.js';
import { ZkVerifier } from './verifier.js';

class PaymentError extends Error {
  public readonly httpStatus: number;
  constructor(
    public readonly code: ZKCredentialErrorCode,
    message: string
  ) {
    super(message);
    this.name = 'PaymentError';
    this.httpStatus = ERROR_CODE_TO_STATUS[code];
  }
}

export interface ZkCredentialConfig {
  /** Service ID this server accepts credentials for */
  serviceId: bigint;
  /** Facilitator's public key for verifying credentials (spec §9.2) */
  facilitatorPubkey: Point;
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
  private getFacilitatorPubkeyPrefixed(): string {
    const xHex = this.config.facilitatorPubkey.x.toString(16).padStart(64, '0');
    const yHex = this.config.facilitatorPubkey.y.toString(16).padStart(64, '0');
    return addSchemePrefix('pedersen-schnorr-poseidon-ultrahonk', `0x04${xHex}${yHex}`);
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
        zk_credential: {
          version: '0.1.0',
          credential_suites: ['pedersen-schnorr-poseidon-ultrahonk'],
          facilitator_pubkey: this.getFacilitatorPubkeyPrefixed(),
          facilitator_url: this.config.facilitatorUrl,
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
   * Express middleware for ZK credential verification (spec §11)
   */
  middleware() {
    return async (req: Request, res: Response, next: NextFunction) => {
      // 0. Handle Payment Settlement (Mediated Flow)
      const paymentBody = req.body as Record<string, unknown> | undefined;
      const payment = (paymentBody as { payment?: unknown } | undefined)?.payment;
      const zkCredential = (paymentBody as { extensions?: { zk_credential?: { commitment?: string } } } | undefined)
        ?.extensions?.zk_credential;
      if (payment) {
        try {
          console.log('[ZkCredential] Processing payment body...');

          if (!paymentBody || typeof paymentBody !== 'object') {
            throw new PaymentError('invalid_proof', 'Missing payment body');
          }

          if (!zkCredential?.commitment) {
            throw new PaymentError(
              'invalid_proof',
              'Missing extensions.zk_credential.commitment per spec §8.2'
            );
          }

          // Call Facilitator /settle
          // Reuse buildPaymentRequirements() to ensure consistency with 402 response
          const settleReq = {
            payment,
            paymentRequirements: this.buildPaymentRequirements(),
            extensions: {
              zk_credential: {
                commitment: zkCredential.commitment,
              },
            },
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
              'service_unavailable',
              'Payment facilitator is temporarily unavailable. Please retry.'
            );
          }

          if (!settleResp.ok) {
            const errBody = await settleResp.text();
            if (settleResp.status >= 400 && settleResp.status < 500) {
              throw new PaymentError(
                'tier_insufficient',
                `Payment rejected by facilitator: ${errBody}`
              );
            } else {
              throw new PaymentError(
                'service_unavailable',
                'Payment facilitator is temporarily unavailable. Please retry.'
              );
            }
          }

          const settleData: unknown = await settleResp.json();

          // Validate settlement response structure (SettlementResponse from facilitator/types.ts)
          if (!settleData || typeof settleData !== 'object') {
            throw new PaymentError(
              'server_error',
              'Payment facilitator returned an invalid response'
            );
          }

          const response = settleData as Record<string, unknown>;

          // Validate payment_receipt
          if (!response.payment_receipt || typeof response.payment_receipt !== 'object') {
            throw new PaymentError(
              'server_error',
              'Settlement response missing payment_receipt'
            );
          }
          const receipt = response.payment_receipt as Record<string, unknown>;
          if (receipt.status !== 'settled') {
            throw new PaymentError(
              'tier_insufficient',
              `Settlement failed: status=${receipt.status}`
            );
          }

          // Validate extensions.zk_credential.credential
          if (!response.extensions || typeof response.extensions !== 'object') {
            throw new PaymentError(
              'server_error',
              'Settlement response missing extensions'
            );
          }
          const extensions = response.extensions as Record<string, unknown>;
          if (!extensions.zk_credential || typeof extensions.zk_credential !== 'object') {
            throw new PaymentError(
              'server_error',
              'Settlement response missing extensions.zk_credential'
            );
          }
          const zkCredExt = extensions.zk_credential as Record<string, unknown>;
          if (!zkCredExt.credential || typeof zkCredExt.credential !== 'object') {
            throw new PaymentError(
              'server_error',
              'Settlement response missing extensions.zk_credential.credential'
            );
          }
          const cred = zkCredExt.credential as Record<string, unknown>;

          // Validate required credential fields
          if (typeof cred.tier !== 'number') {
            throw new PaymentError(
              'server_error',
              'Settlement response credential missing tier'
            );
          }

          // Construct X402PaymentResponse
          const clientResp = {
            x402: {
              payment_response: response.payment_receipt,
            },
            zk_credential: {
              credential: cred,
            },
          };

          console.log('[ZkCredential] Payment settled, credential issued. Returning credential.');
          res.status(200).json(clientResp);
          return;

        } catch (error) {
          console.error('[ZkCredential] Payment processing failed:', error instanceof Error ? error.message : String(error));

          if (error instanceof PaymentError) {
            res.status(error.httpStatus).json({
              error: error.code,
              message: error.message,
            });
            return;
          }

          // Unknown error - return 500 to avoid silent failures
          res.status(500).json({
            error: 'server_error',
            message: 'An unexpected error occurred processing payment',
          });
          return;
        }
      }

      const result = await this.verifyRequest(req);

      if (!result.valid) {
        // 402: Payment Required when no credentials provided (spec §6)
        // Prompts client to discover payment requirements and obtain credentials
        const hasPresentation = !!(paymentBody && typeof paymentBody === 'object' && 'zk_credential' in paymentBody);
        if (!hasPresentation) {
          const resourceUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
          res.status(402).json(this.build402Response(resourceUrl));
          return;
        }

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

      // Attach credential info to request
      req.zkCredential = {
        tier: result.tier,
        originToken: result.originToken,
      };

      next();
    };
  }

  /**
   * Parse zk_credential envelope from request body (spec §6.3)
   */
  private parseProofEnvelope(req: Request): {
    suite: string;
    kid?: string;
    proofB64: string;
    currentTime: number;
    publicOutputs: { originToken: string; tier: number };
  } | null {
    const body = req.body as Record<string, unknown> | undefined;
    const zkCredential = (body as { zk_credential?: Record<string, unknown> } | undefined)?.zk_credential;
    if (!zkCredential || typeof zkCredential !== 'object') {
      return null;
    }

    const suite = zkCredential.suite;
    const kid = zkCredential.kid;
    const proofB64 = zkCredential.proof;
    const currentTime = zkCredential.current_time;
    const publicOutputs = zkCredential.public_outputs as Record<string, unknown> | undefined;

    if (typeof suite !== 'string' || typeof proofB64 !== 'string' || !publicOutputs) {
      return null;
    }

    const originToken = publicOutputs.origin_token;
    const tier = publicOutputs.tier;

    if (typeof originToken !== 'string' || typeof tier !== 'number') {
      return null;
    }
    // current_time is required — the proof is bound to the exact value used during
    // generation, so the server cannot substitute its own clock (§6.3, §11.1)
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
      kid: typeof kid === 'string' ? kid : undefined,
      proofB64,
      currentTime,
      publicOutputs: { originToken, tier },
    };
  }

  /**
   * Strictly validate a base64 string
   * Node's Buffer.from() is lenient and may ignore invalid characters.
   * This performs strict validation using regex and round-trip check.
   */
  private isValidBase64(str: string): boolean {
    // Empty string is not valid base64
    if (str.length === 0) {
      return false;
    }

    // Check if string contains only valid base64 characters
    // Valid base64: A-Z, a-z, 0-9, +, /, and optional padding with =
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(str)) {
      return false;
    }

    // Perform round-trip check: decode then encode should match original
    try {
      const decoded = Buffer.from(str, 'base64');
      const reencoded = decoded.toString('base64');
      return str === reencoded;
    } catch {
      return false;
    }
  }

  /**
   * Verify a request's ZK credential (spec §15)
   * 
   * Verification flow:
   * 1. Parse request body for zk_credential
   * 2. If missing → credential_missing
   * 3. Check suite support
   * 4. Construct public inputs: (service_id, current_time, origin_id, facilitator_pubkey)
   * 5. Verify proof
   * 6. Extract outputs: (origin_token, tier)
   * 7. Check tier meets endpoint requirement
   * 8. Return success (rate limiting handled by middleware)
   */
  async verifyRequest(req: Request): Promise<CredentialVerificationResult> {
    // Step 1-2: Parse request body
    const presentation = this.parseProofEnvelope(req);
    if (!presentation) {
      return { valid: false, errorCode: 'credential_missing', message: 'Missing zk_credential presentation' };
    }

    // Step 3: Check suite
    if (presentation.suite !== 'pedersen-schnorr-poseidon-ultrahonk') {
      return { valid: false, errorCode: 'unsupported_suite', message: `Unsupported suite: ${presentation.suite}` };
    }

    // Step 3.5: Strictly validate base64 proof encoding
    if (!this.isValidBase64(presentation.proofB64)) {
      return { valid: false, errorCode: 'invalid_proof', message: 'Invalid proof encoding' };
    }

    const proofBytes = Buffer.from(presentation.proofB64, 'base64');

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
      bigIntToHex(this.config.facilitatorPubkey.x),
      bigIntToHex(this.config.facilitatorPubkey.y),
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

  /**
  * Compute origin_id for a request
  * Spec normalization: poseidon(stringToField(scheme + "://" + host + path))
  * - scheme/host lowercase
  * - path preserves case, strips trailing slash
  * - query excluded
   */
  private computeOriginId(req: Request): bigint {
    const url = new URL(req.originalUrl, `${req.protocol}://${req.get('host')}`);

    const scheme = url.protocol.replace(':', '').toLowerCase();
    const hostname = url.hostname.toLowerCase();
    const port = url.port;
    const defaultPort = scheme === 'https' ? '443' : scheme === 'http' ? '80' : '';
    const host = port && port !== defaultPort ? `${hostname}:${port}` : hostname;

    let pathname = url.pathname;
    if (pathname.endsWith('/') && pathname.length > 1) {
      pathname = pathname.slice(0, -1);
    }

    const canonicalOrigin = `${scheme}://${host}${pathname}`;
    const originField = stringToField(canonicalOrigin);
    return poseidonHash3(originField, 0n, 0n);
  }

  /**
   * Get rate limiter stats
   */
  getStats() {
    return this.rateLimiter.stats();
  }
}
