import test from 'node:test';
import assert from 'node:assert/strict';
import { issueToken, verifyToken, authorizeCapability, timingSafeEqualString } from '../src/security/auth.ts';
import { AuthenticationError, AuthorizationError } from '../src/security/errors.ts';

const MASTER_KEY = 'super-strong-fortress-cryptographic-key-32chars!';

test('Auth: issues and successfully verifies valid signed bearer token', async () => {
  const token = await issueToken(
    {
      id: 'usr-uae-secops',
      username: 'fatima.alhosani',
      role: 'SECOPS',
      tenantId: 'uae-cert',
    },
    MASTER_KEY,
    3600
  );

  assert.ok(typeof token === 'string');
  assert.equal(token.split('.').length, 3);

  const payload = await verifyToken(token, MASTER_KEY);
  assert.equal(payload.sub, 'usr-uae-secops');
  assert.equal(payload.role, 'SECOPS');
  assert.ok(payload.permissions.includes('execute:remediation'));
});

test('Auth: detects and rejects tampered token payload or signature', async () => {
  const token = await issueToken(
    {
      id: 'usr-001',
      username: 'analyst',
      role: 'AUDIT',
      tenantId: 'dept-finance',
    },
    MASTER_KEY,
    3600
  );

  const parts = token.split('.');
  // Tamper with payload by changing role inside base64 string
  const fakePayload = Buffer.from(
    JSON.stringify({ sub: 'usr-001', role: 'ADMIN', exp: Math.floor(Date.now() / 1000) + 3600 })
  ).toString('base64url');
  const forgedToken = `${parts[0]}.${fakePayload}.${parts[2]}`;

  await assert.rejects(
    async () => verifyToken(forgedToken, MASTER_KEY),
    AuthenticationError
  );
});

test('Auth: rejects expired token', async () => {
  // Issue token with -10 second TTL (already expired)
  const expiredToken = await issueToken(
    {
      id: 'usr-old',
      username: 'expired_user',
      role: 'SERVICE',
      tenantId: 'tenant-old',
    },
    MASTER_KEY,
    -10
  );

  await assert.rejects(
    async () => verifyToken(expiredToken, MASTER_KEY),
    (err: Error) => err instanceof AuthenticationError && err.message.includes('Token expired')
  );
});

test('Auth: enforces RBAC capability boundaries', async () => {
  const token = await issueToken(
    {
      id: 'usr-service',
      username: 'metrics-service',
      role: 'SERVICE',
      tenantId: 'telemetry',
    },
    MASTER_KEY,
    3600
  );

  const payload = await verifyToken(token, MASTER_KEY);

  // SERVICE can read telemetry
  assert.doesNotThrow(() => authorizeCapability(payload, 'read:telemetry'));

  // SERVICE cannot write policy or rotate keys
  assert.throws(
    () => authorizeCapability(payload, 'write:policy'),
    AuthorizationError
  );
  assert.throws(
    () => authorizeCapability(payload, 'rotate:keys'),
    AuthorizationError
  );
});

test('Auth: timing-safe string comparison handles equal and unequal lengths safely', () => {
  assert.equal(timingSafeEqualString('secret_token_123', 'secret_token_123'), true);
  assert.equal(timingSafeEqualString('secret_token_123', 'secret_token_124'), false);
  assert.equal(timingSafeEqualString('secret', 'secret_longer'), false);
});
