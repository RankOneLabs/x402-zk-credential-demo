/**
 * ZK Session Client
 * 
 * Manages credentials and generates authenticated requests.
 */

import {
  pedersenCommit,
  randomFieldElement,
  poseidonHash3,
  stringToField,
  bigIntToHex,
  hexToBigInt,
} from '@demo/crypto';
import { CredentialStorage, type StoredCredential } from './storage.js';
import { ProofCache, type CachedProof } from './cache.js';

export type PresentationStrategy =
  | 'max-privacy'      // Always increment index
  | 'max-performance'  // Always reuse index=0
  | 'per-origin'       // One index per origin
  | 'time-bucketed';   // New index every N seconds

export interface ClientConfig {
  /** Presentation strategy */
  strategy: PresentationStrategy;
  /** Time bucket size in seconds (for time-bucketed strategy) */
  timeBucketSeconds: number;
  /** Enable proof caching */
  enableProofCache: boolean;
  /** Storage path (optional) */
  storagePath?: string;
}

const DEFAULT_CONFIG: ClientConfig = {
  strategy: 'time-bucketed',
  timeBucketSeconds: 300, // 5 minutes
  enableProofCache: true,
};

export class ZkSessionClient {
  private readonly config: ClientConfig;
  private readonly storage: CredentialStorage;
  private readonly proofCache: ProofCache;
  private readonly originIndices: Map<string, number> = new Map();

  constructor(config: Partial<ClientConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.storage = new CredentialStorage(this.config.storagePath);
    this.proofCache = new ProofCache();
  }

  /**
   * Obtain a credential from an issuer
   */
  async obtainCredential(
    issuerUrl: string,
    paymentProof: {
      mock?: { amountUSDC: number; payer: string };
      txHash?: string;
    }
  ): Promise<StoredCredential> {
    // Generate secrets
    const nullifierSeed = randomFieldElement();
    const blindingFactor = randomFieldElement();

    // Compute commitment (async - uses Barretenberg)
    const commitment = await pedersenCommit(nullifierSeed, blindingFactor);

    // Request credential from issuer
    const response = await fetch(`${issuerUrl}/credentials/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        paymentProof,
        userCommitment: {
          x: bigIntToHex(commitment.point.x),
          y: bigIntToHex(commitment.point.y),
        },
      }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: response.statusText })) as { error: string };
      throw new Error(`Failed to obtain credential: ${error.error}`);
    }

    const data = await response.json() as { credential: any };
    const { credential } = data;

    // Store with secrets
    const stored: StoredCredential = {
      ...credential,
      nullifierSeed: bigIntToHex(nullifierSeed),
      blindingFactor: bigIntToHex(blindingFactor),
      presentationCount: 0,
      obtainedAt: Date.now(),
      issuerUrl,
    };

    this.storage.set(stored);
    return stored;
  }

  /**
   * Make an authenticated request
   */
  async makeAuthenticatedRequest(
    url: string,
    options: RequestInit & { forceUnlinkable?: boolean } = {}
  ): Promise<Response> {
    const urlObj = new URL(url);
    const originId = stringToField(urlObj.pathname);

    // Find credential for this service
    // For demo, use the first available credential
    const credentials = this.storage.list();
    if (credentials.length === 0) {
      throw new Error('No credentials available. Obtain one first.');
    }

    const credential = credentials[0];

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (credential.expiresAt < now) {
      throw new Error('Credential expired. Obtain a new one.');
    }

    // Select presentation index based on strategy
    const { index, timeBucket } = this.selectPresentationIndex(
      credential,
      originId,
      options.forceUnlinkable
    );

    // Check if we have a cached proof
    const cachedProof = this.config.enableProofCache
      ? this.proofCache.get(
        credential.serviceId,
        originId.toString(),
        index,
        timeBucket
      )
      : undefined;

    let proof: CachedProof;

    if (cachedProof) {
      console.log('[Client] Cache hit, reusing proof');
      proof = cachedProof;
    } else {
      console.log('[Client] Generating new proof...');
      proof = await this.generateProof(credential, originId, index, timeBucket);

      // Cache the proof
      if (this.config.enableProofCache) {
        this.proofCache.set(
          credential.serviceId,
          originId.toString(),
          index,
          proof,
          timeBucket
        );
      }
    }

    // Add ZK session headers
    const headers = new Headers(options.headers);
    headers.set('ZK-SESSION-PROOF', proof.proof);
    headers.set('ZK-SESSION-TOKEN', proof.originToken);
    headers.set('ZK-SESSION-TIER', proof.tier.toString());

    return fetch(url, { ...options, headers });
  }

  /**
   * Generate a ZK proof
   */
  private async generateProof(
    credential: StoredCredential,
    originId: bigint,
    presentationIndex: number,
    timeBucket?: number
  ): Promise<CachedProof> {
    // TODO: Use @noir-lang/noir_js for actual proof generation
    // Generates random bytes as a placeholder proof for demo mode (skipProofVerification)

    const nullifierSeed = hexToBigInt(credential.nullifierSeed);

    // Compute origin_token = H(nullifier_seed, origin_id, presentation_index)
    const originToken = poseidonHash3(
      nullifierSeed,
      originId,
      BigInt(presentationIndex)
    );

    // Mock proof (base64 of random bytes) - placeholder
    const mockProofBytes = new Uint8Array(128);
    crypto.getRandomValues(mockProofBytes);
    const mockProof = Buffer.from(mockProofBytes).toString('base64');

    // Expiration: use time bucket end or 60 seconds
    const expiresAt = timeBucket
      ? timeBucket + this.config.timeBucketSeconds
      : Math.floor(Date.now() / 1000) + 60;

    return {
      proof: mockProof,
      originToken: bigIntToHex(originToken),
      tier: credential.tier,
      expiresAt,
      meta: {
        serviceId: credential.serviceId,
        originId: originId.toString(),
        presentationIndex,
        timeBucket,
      },
    };
  }

  /**
   * Select presentation index based on strategy
   */
  private selectPresentationIndex(
    credential: StoredCredential,
    originId: bigint,
    forceUnlinkable?: boolean
  ): { index: number; timeBucket?: number } {
    // Force unlinkable overrides strategy
    if (forceUnlinkable) {
      const index = this.storage.incrementPresentationCount(credential.serviceId) - 1;
      return { index };
    }

    switch (this.config.strategy) {
      case 'max-privacy': {
        const index = this.storage.incrementPresentationCount(credential.serviceId) - 1;
        return { index };
      }

      case 'max-performance':
        return { index: 0 };

      case 'per-origin': {
        const originKey = originId.toString();
        if (!this.originIndices.has(originKey)) {
          const index = this.storage.incrementPresentationCount(credential.serviceId) - 1;
          this.originIndices.set(originKey, index);
        }
        return { index: this.originIndices.get(originKey)! };
      }

      case 'time-bucketed': {
        const now = Math.floor(Date.now() / 1000);
        const bucket = Math.floor(now / this.config.timeBucketSeconds);
        const timeBucket = bucket * this.config.timeBucketSeconds;
        const index = bucket % credential.maxPresentations;
        return { index, timeBucket };
      }

      default:
        return { index: 0 };
    }
  }

  /**
   * List stored credentials
   */
  listCredentials(): StoredCredential[] {
    return this.storage.list();
  }

  /**
   * Get credential status
   */
  getCredentialStatus(serviceId?: string): {
    credential: StoredCredential;
    status: 'valid' | 'expired' | 'exhausted';
    remainingPresentations: number;
    expiresIn: number;
  } | undefined {
    const credentials = this.storage.list();
    const credential = serviceId
      ? credentials.find(c => c.serviceId === serviceId)
      : credentials[0];

    if (!credential) {
      return undefined;
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresIn = credential.expiresAt - now;
    const remaining = credential.maxPresentations - credential.presentationCount;

    let status: 'valid' | 'expired' | 'exhausted';
    if (expiresIn <= 0) {
      status = 'expired';
    } else if (remaining <= 0) {
      status = 'exhausted';
    } else {
      status = 'valid';
    }

    return {
      credential,
      status,
      remainingPresentations: Math.max(0, remaining),
      expiresIn: Math.max(0, expiresIn),
    };
  }

  /**
   * Clear all stored credentials
   */
  clearCredentials(): void {
    this.storage.clear();
    this.proofCache.clear();
    this.originIndices.clear();
  }
}
