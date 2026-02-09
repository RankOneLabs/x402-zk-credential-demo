/**
 * Proof Cache
 * 
 * Caches ZK proofs for reuse when using the same identity_index.
 */

export interface CachedProof {
  /** Base64-encoded proof */
  proof: string;
  /** Origin token (public output) */
  originToken: string;
  /** Tier (public output) */
  tier: number;
  /** The current_time used when generating the proof (public input) */
  currentTime: number;
  /** When this cache entry expires (set by caller, e.g. credential expiresAt) */
  cachedUntil: number;
  /** Cache key components for debugging */
  meta: {
    serviceId: string;
    originId: string;
    identityIndex: number;
    timeBucket?: number;
  };
}

export class ProofCache {
  private cache: Map<string, CachedProof> = new Map();
  private readonly maxSize: number;

  constructor(maxSize = 100) {
    this.maxSize = maxSize;
  }

  /**
   * Compute cache key
   */
  private computeKey(
    serviceId: string,
    originId: string,
    identityIndex: number,
    timeBucket?: number
  ): string {
    return `${serviceId}:${originId}:${identityIndex}:${timeBucket ?? 'none'}`;
  }

  /**
   * Get cached proof if valid
   */
  get(
    serviceId: string,
    originId: string,
    identityIndex: number,
    timeBucket?: number
  ): CachedProof | undefined {
    const key = this.computeKey(serviceId, originId, identityIndex, timeBucket);
    const cached = this.cache.get(key);

    if (!cached) {
      return undefined;
    }

    // Check expiration
    if (cached.cachedUntil < Math.floor(Date.now() / 1000)) {
      this.cache.delete(key);
      return undefined;
    }

    return cached;
  }

  /**
   * Store proof in cache
   */
  set(
    serviceId: string,
    originId: string,
    identityIndex: number,
    proof: CachedProof,
    timeBucket?: number
  ): void {
    const key = this.computeKey(serviceId, originId, identityIndex, timeBucket);

    // Prune if at capacity
    if (this.cache.size >= this.maxSize) {
      this.prune();
    }

    this.cache.set(key, {
      ...proof,
      meta: { serviceId, originId, identityIndex, timeBucket },
    });
  }

  /**
   * Remove expired entries and oldest if still at capacity
   */
  prune(): number {
    const now = Math.floor(Date.now() / 1000);
    let pruned = 0;

    // Remove expired
    for (const [key, value] of this.cache) {
      if (value.cachedUntil < now) {
        this.cache.delete(key);
        pruned++;
      }
    }

    // If still at capacity, remove oldest (first inserted)
    while (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) {
        this.cache.delete(firstKey);
        pruned++;
      } else {
        break;
      }
    }

    return pruned;
  }

  /**
   * Clear all cached proofs
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  stats(): { size: number; maxSize: number } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
    };
  }
}
