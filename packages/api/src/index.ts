/**
 * @demo/api
 * 
 * API server with ZK proof verification middleware.
 */

export { ZkCredentialMiddleware, type ZkCredentialConfig } from './middleware.js';
export { createApiServer, type ApiServerConfig } from './server.js';
export { RateLimiter, type RateLimitConfig, type RateLimitEntry } from './ratelimit.js';
export { ZkVerifier, type VerifierConfig, type ProofData, type ProofVerificationResult } from './verifier.js';
export { type CredentialVerificationResult } from './middleware.js';
