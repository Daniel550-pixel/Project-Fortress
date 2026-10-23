import test from 'node:test';
import assert from 'node:assert/strict';
import { validateAndLoadConfig, maskConfig } from '../src/security/config.ts';
import { ValidationError } from '../src/security/errors.ts';

test('Config: successfully validates a production-ready secure configuration', () => {
  const env = {
    NODE_ENV: 'production',
    PORT: '8443',
    FORTRESS_HMAC_SECRET: 'a-super-secret-key-that-is-at-least-32-chars-long!',
    TOKEN_TTL_SECONDS: '1800',
    RATE_LIMIT_WINDOW_MS: '60000',
    RATE_LIMIT_MAX_REQUESTS: '50',
    ALLOWED_ORIGINS: 'https://fortress.internal.gov.ae',
  };

  const config = validateAndLoadConfig(env);
  assert.equal(config.nodeEnv, 'production');
  assert.equal(config.port, 8443);
  assert.equal(config.rateLimitMaxRequests, 50);
  assert.equal(config.allowedOrigins[0], 'https://fortress.internal.gov.ae');

  // Verify masking
  const masked = maskConfig(config);
  assert.ok(String(masked.hmacSecret).includes('***REDACTED'));
});

test('Config: rejects HMAC secret shorter than 32 characters', () => {
  assert.throws(
    () => {
      validateAndLoadConfig({
        FORTRESS_HMAC_SECRET: 'short-key',
      });
    },
    ValidationError
  );
});

test('Config: rejects known trivial weak keys', () => {
  assert.throws(
    () => {
      validateAndLoadConfig({
        FORTRESS_HMAC_SECRET: '12345678901234567890123456789012',
      });
    },
    (err: Error) => err instanceof ValidationError && err.message.includes('commonly known weak')
  );
});

test('Config: rejects wildcard CORS in production environment', () => {
  assert.throws(
    () => {
      validateAndLoadConfig({
        NODE_ENV: 'production',
        FORTRESS_HMAC_SECRET: 'long-enough-secret-key-for-fortress-32!',
        ALLOWED_ORIGINS: '*',
      });
    },
    (err: Error) => err instanceof ValidationError && err.message.includes('Wildcard CORS')
  );
});

test('Config: rejects privileged ports (< 1024)', () => {
  assert.throws(
    () => {
      validateAndLoadConfig({
        PORT: '80',
        FORTRESS_HMAC_SECRET: 'long-enough-secret-key-for-fortress-32!',
      });
    },
    ValidationError
  );
});
