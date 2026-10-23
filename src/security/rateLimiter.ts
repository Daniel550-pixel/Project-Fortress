/**
 * Project Fortress — Token Bucket & Sliding Window Rate Limiter
 * @license Apache-2.0
 */

import { RateLimitStatus } from './types.ts';
import { RateLimitExceededError } from './errors.ts';

interface Bucket {
  tokens: number;
  lastRefill: number;
}

export class TokenBucketRateLimiter {
  private buckets = new Map<string, Bucket>();
  private readonly capacity: number;
  private readonly refillTokensPerSec: number;
  private readonly windowMs: number;

  constructor(maxRequests = 100, windowMs = 60000) {
    this.capacity = maxRequests;
    this.windowMs = windowMs;
    this.refillTokensPerSec = maxRequests / (windowMs / 1000);

    // Periodic cleanup of stale entries every 5 minutes
    if (typeof setInterval !== 'undefined') {
      const timer = setInterval(() => this.cleanupStaleBuckets(), 300000);
      if (typeof timer.unref === 'function') {
        timer.unref();
      }
    }
  }

  /**
   * Attempts to consume N tokens for a given identifier (IP or token).
   */
  public consume(clientId: string, tokensRequested = 1): RateLimitStatus {
    const now = Date.now();
    let bucket = this.buckets.get(clientId);

    if (!bucket) {
      bucket = { tokens: this.capacity, lastRefill: now };
      this.buckets.set(clientId, bucket);
    } else {
      // Calculate token replenishment
      const elapsedSeconds = (now - bucket.lastRefill) / 1000;
      const refilled = elapsedSeconds * this.refillTokensPerSec;
      bucket.tokens = Math.min(this.capacity, bucket.tokens + refilled);
      bucket.lastRefill = now;
    }

    if (bucket.tokens >= tokensRequested) {
      bucket.tokens -= tokensRequested;
      return {
        allowed: true,
        limit: this.capacity,
        remaining: Math.floor(bucket.tokens),
        resetMs: Math.ceil(((this.capacity - bucket.tokens) / this.refillTokensPerSec) * 1000),
      };
    }

    // Rate limit hit
    const deficit = tokensRequested - bucket.tokens;
    const retryAfterSec = Math.max(1, Math.ceil(deficit / this.refillTokensPerSec));

    return {
      allowed: false,
      limit: this.capacity,
      remaining: 0,
      resetMs: retryAfterSec * 1000,
      retryAfterSec,
    };
  }

  /**
   * Asserts rate limit compliance, throwing RateLimitExceededError if breached.
   */
  public assertAllowed(clientId: string, tokensRequested = 1): RateLimitStatus {
    const status = this.consume(clientId, tokensRequested);
    if (!status.allowed) {
      throw new RateLimitExceededError(status.retryAfterSec || 1);
    }
    return status;
  }

  public reset(clientId: string): void {
    this.buckets.delete(clientId);
  }

  public resetAll(): void {
    this.buckets.clear();
  }

  private cleanupStaleBuckets(): void {
    const now = Date.now();
    const staleThresholdMs = this.windowMs * 2;
    for (const [key, b] of this.buckets.entries()) {
      if (now - b.lastRefill > staleThresholdMs) {
        this.buckets.delete(key);
      }
    }
  }
}

export const defaultRateLimiter = new TokenBucketRateLimiter(60, 60000);
