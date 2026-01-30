import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { RateLimiter } from '../src/ratelimit.js';

describe('RateLimiter', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-29T12:00:00Z'));
    
    limiter = new RateLimiter({
      maxRequestsPerToken: 10,
      windowSeconds: 60,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('check', () => {
    it('should allow requests within limit', () => {
      const result = limiter.check('token1');
      
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(9);
    });

    it('should decrement remaining count', () => {
      limiter.check('token1');
      limiter.check('token1');
      const result = limiter.check('token1');
      
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(7);
    });

    it('should block after limit exceeded', () => {
      // Use all 10 requests
      for (let i = 0; i < 10; i++) {
        limiter.check('token1');
      }
      
      const result = limiter.check('token1');
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });

    it('should reset after window expires', () => {
      // Use all requests
      for (let i = 0; i < 10; i++) {
        limiter.check('token1');
      }
      
      // Advance past window
      vi.advanceTimersByTime(61_000);
      
      const result = limiter.check('token1');
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(9);
    });

    it('should track tokens independently', () => {
      // Use all requests for token1
      for (let i = 0; i < 10; i++) {
        limiter.check('token1');
      }
      
      // token2 should still be allowed
      const result = limiter.check('token2');
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(9);
    });

    it('should return correct resetAt time', () => {
      const now = Math.floor(Date.now() / 1000);
      const result = limiter.check('token1');
      
      expect(result.resetAt).toBe(now + 60);
    });
  });

  describe('getState', () => {
    it('should return undefined for unknown token', () => {
      expect(limiter.getState('unknown')).toBeUndefined();
    });

    it('should return state for known token', () => {
      limiter.check('token1');
      limiter.check('token1');
      
      const state = limiter.getState('token1');
      expect(state?.count).toBe(2);
    });
  });

  describe('prune', () => {
    it('should remove expired entries', () => {
      limiter.check('token1');
      limiter.check('token2');
      
      expect(limiter.stats().totalTokens).toBe(2);
      
      // Advance past window
      vi.advanceTimersByTime(61_000);
      
      const pruned = limiter.prune();
      expect(pruned).toBe(2);
      expect(limiter.stats().totalTokens).toBe(0);
    });

    it('should keep non-expired entries', () => {
      limiter.check('token1');
      
      // Advance but not past window
      vi.advanceTimersByTime(30_000);
      
      limiter.check('token2');
      
      // Advance past token1's window but not token2's
      vi.advanceTimersByTime(35_000);
      
      const pruned = limiter.prune();
      expect(pruned).toBe(1);
      expect(limiter.getState('token1')).toBeUndefined();
      expect(limiter.getState('token2')).toBeDefined();
    });
  });

  describe('stats', () => {
    it('should return correct statistics', () => {
      limiter.check('token1');
      limiter.check('token1');
      limiter.check('token2');
      limiter.check('token3');
      limiter.check('token3');
      limiter.check('token3');
      
      const stats = limiter.stats();
      expect(stats.totalTokens).toBe(3);
      expect(stats.totalRequests).toBe(6);
    });

    it('should return zeros for empty limiter', () => {
      const stats = limiter.stats();
      expect(stats.totalTokens).toBe(0);
      expect(stats.totalRequests).toBe(0);
    });
  });
});
