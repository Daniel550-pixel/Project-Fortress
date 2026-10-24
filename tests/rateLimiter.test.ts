import test from 'node:test';
import assert from 'node:assert/strict';
import { TokenBucketRateLimiter } from '../src/security/rateLimiter.ts';
import { RateLimitExceededError, ValidationError } from '../src/security/errors.ts';

test('RateLimiter: permits bursts up to capacity and blocks excess requests', () => {
  const limiter = new TokenBucketRateLimiter(3, 10000); // 3 tokens per 10s
  const clientId = 'client-192.0.2.1';

  // Consume first 3 tokens
  assert.equal(limiter.consume(clientId).allowed, true);
  assert.equal(limiter.consume(clientId).allowed, true);
  assert.equal(limiter.consume(clientId).allowed, true);

  // 4th request must be rejected
  const blocked = limiter.consume(clientId);
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.remaining, 0);
  assert.ok((blocked.retryAfterSec || 0) > 0);

  // assertAllowed should throw RateLimitExceededError
  assert.throws(
    () => limiter.assertAllowed(clientId),
    RateLimitExceededError
  );
});

test('RateLimiter: isolates quotas between distinct clients', () => {
  const limiter = new TokenBucketRateLimiter(2, 5000);

  limiter.consume('client-A');
  limiter.consume('client-A');
  assert.equal(limiter.consume('client-A').allowed, false);

  // client-B should still have full quota
  assert.equal(limiter.consume('client-B').allowed, true);
  assert.equal(limiter.consume('client-B').allowed, true);
});

test('RateLimiter: rejects negative, zero, NaN, or non-finite token requests', () => {
  const limiter = new TokenBucketRateLimiter(10, 60000);

  assert.throws(() => limiter.consume('client-test', -5), ValidationError);
  assert.throws(() => limiter.consume('client-test', 0), ValidationError);
  assert.throws(() => limiter.consume('client-test', NaN), ValidationError);
  assert.throws(() => limiter.consume('client-test', Infinity), ValidationError);
});
