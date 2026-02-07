/**
 * Credential Storage
 * 
 * Stores credentials securely on disk.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import type { Point, SchnorrSignature } from '@demo/crypto';

export interface StoredCredential {
  // Credential from issuer
  serviceId: string;
  tier: number;
  identityLimit: number;
  issuedAt: number;
  expiresAt: number;
  userCommitment: { x: string; y: string };
  signature: { r: { x: string; y: string }; s: string };
  facilitatorPubkey: { x: string; y: string };

  // User secrets
  nullifierSeed: string;
  blindingFactor: string;

  // Tracking
  identityCount: number;
  obtainedAt: number;
  facilitatorUrl: string;
}

export interface StorageData {
  version: number;
  credentials: Record<string, StoredCredential>;
}

export class CredentialStorage {
  private readonly storagePath: string;
  private data: StorageData;

  constructor(storagePath?: string) {
    this.storagePath = storagePath ?? join(homedir(), '.zk-credential', 'credentials.json');
    this.data = this.load();
  }

  /**
   * Load credentials from disk
   */
  private load(): StorageData {
    try {
      if (existsSync(this.storagePath)) {
        const content = readFileSync(this.storagePath, 'utf-8');
        return JSON.parse(content);
      }
    } catch (err) {
      console.error('[Storage] Failed to load credentials:', err);
    }

    return { version: 1, credentials: {} };
  }

  /**
   * Save credentials to disk
   */
  private save(): void {
    try {
      const dir = dirname(this.storagePath);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
      writeFileSync(this.storagePath, JSON.stringify(this.data, null, 2));
    } catch (err) {
      console.error('[Storage] Failed to save credentials:', err);
    }
  }

  /**
   * Get credential by service ID
   */
  get(serviceId: string): StoredCredential | undefined {
    return this.data.credentials[serviceId];
  }

  /**
   * Store a credential
   */
  set(credential: StoredCredential): void {
    this.data.credentials[credential.serviceId] = credential;
    this.save();
  }

  /**
   * Remove a credential
   */
  remove(serviceId: string): void {
    delete this.data.credentials[serviceId];
    this.save();
  }

  /**
   * List all credentials
   */
  list(): StoredCredential[] {
    return Object.values(this.data.credentials);
  }

  /**
   * Increment identity count
   */
  incrementIdentityCount(serviceId: string): number {
    const cred = this.data.credentials[serviceId];
    if (!cred) {
      throw new Error(`No credential for service ${serviceId}`);
    }

    cred.identityCount++;
    this.save();
    return cred.identityCount;
  }

  /**
   * Clear all credentials
   */
  clear(): void {
    this.data = { version: 1, credentials: {} };
    this.save();
  }
}
