/**
 * In-Memory Rate Limiter
 * 
 * Tracks request counts per origin_token with sliding window.
 */

export interface RateLimitConfig {
  /** Maximum requests per token per window */
  maxRequestsPerToken: number;
  /** Window size in seconds */
  windowSeconds: number;
}

export interface RateLimitEntry {
  count: number;
  windowStart: number;
}

export class RateLimiter {
  private entries: Map<string, RateLimitEntry> = new Map();
  
  constructor(private readonly config: RateLimitConfig) {}
  
  /**
   * Check if a token is within rate limits
   * @returns true if allowed, false if rate limited
   */
  check(token: string): { allowed: boolean; remaining: number; resetAt: number } {
    const now = Math.floor(Date.now() / 1000);
    const entry = this.entries.get(token);
    
    // New token or expired window
    if (!entry || now - entry.windowStart >= this.config.windowSeconds) {
      this.entries.set(token, { count: 1, windowStart: now });
      return {
        allowed: true,
        remaining: this.config.maxRequestsPerToken - 1,
        resetAt: now + this.config.windowSeconds,
      };
    }
    
    // Check limit
    if (entry.count >= this.config.maxRequestsPerToken) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: entry.windowStart + this.config.windowSeconds,
      };
    }
    
    // Increment and allow
    entry.count++;
    return {
      allowed: true,
      remaining: this.config.maxRequestsPerToken - entry.count,
      resetAt: entry.windowStart + this.config.windowSeconds,
    };
  }
  
  /**
   * Get current state for a token
   */
  getState(token: string): RateLimitEntry | undefined {
    return this.entries.get(token);
  }
  
  /**
   * Clear expired entries (call periodically)
   */
  prune(): number {
    const now = Math.floor(Date.now() / 1000);
    let pruned = 0;
    
    for (const [token, entry] of this.entries) {
      if (now - entry.windowStart >= this.config.windowSeconds) {
        this.entries.delete(token);
        pruned++;
      }
    }
    
    return pruned;
  }
  
  /**
   * Get statistics
   */
  stats(): { totalTokens: number; totalRequests: number } {
    let totalRequests = 0;
    for (const entry of this.entries.values()) {
      totalRequests += entry.count;
    }
    return {
      totalTokens: this.entries.size,
      totalRequests,
    };
  }
}
