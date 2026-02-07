/**
 * @demo/cli
 * 
 * CLI client for ZK credentials.
 */

export { ZkCredentialClient, type ClientConfig, type IdentityStrategy } from './client.js';
export { CredentialStorage, type StoredCredential } from './storage.js';
export { ProofCache, type CachedProof } from './cache.js';
