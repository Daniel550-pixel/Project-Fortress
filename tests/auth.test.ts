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

test('Auth: rejects algorithm confusion and invalid header types', async () => {
  const validToken = await issueToken(
    { id: 'usr-1', username: 'alice', role: 'ADMIN', tenantId: 't1' },
    MASTER_KEY,
    3600
  );
  const parts = validToken.split('.');

  // 1. None algorithm attack
  const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'FORTRESS-TOKEN' })).toString('base64url');
  await assert.rejects(
    async () => verifyToken(`${noneHeader}.${parts[1]}.${parts[2]}`, MASTER_KEY),
    (err: Error) => err instanceof AuthenticationError && err.message.includes('signature verification failed')
  );

  // 2. Unsupported RS256 algorithm with valid signature matching that header
  const rs256Header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'FORTRESS-TOKEN' })).toString('base64url');
  const { createHmacSignature } = await import('../src/security/auth.ts');
  const rsSig = await createHmacSignature(`${rs256Header}.${parts[1]}`, MASTER_KEY);
  await assert.rejects(
    async () => verifyToken(`${rs256Header}.${parts[1]}.${rsSig}`, MASTER_KEY),
    (err: Error) => err instanceof AuthenticationError && err.message.includes('Only HS256 permitted')
  );

  // 3. Invalid header type
  const badTypHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const badTypSig = await createHmacSignature(`${badTypHeader}.${parts[1]}`, MASTER_KEY);
  await assert.rejects(
    async () => verifyToken(`${badTypHeader}.${parts[1]}.${badTypSig}`, MASTER_KEY),
    (err: Error) => err instanceof AuthenticationError && err.message.includes('Expected FORTRESS-TOKEN')
  );
});

test('Auth: rejects malformed, empty, or future-issued payloads', async () => {
  const { createHmacSignature } = await import('../src/security/auth.ts');
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'FORTRESS-TOKEN' })).toString('base64url');

  // 1. Empty payload {}
  const emptyPayload = Buffer.from(JSON.stringify({})).toString('base64url');
  const emptySig = await createHmacSignature(`${header}.${emptyPayload}`, MASTER_KEY);
  await assert.rejects(
    async () => verifyToken(`${header}.${emptyPayload}.${emptySig}`, MASTER_KEY),
    (err: Error) => err instanceof AuthenticationError && err.message.includes('missing valid subject')
  );

  // 2. Future-issued token (iat in future)
  const futureNow = Math.floor(Date.now() / 1000) + 1000;
  const futurePayload = Buffer.from(JSON.stringify({
    sub: 'usr-future',
    username: 'time-traveler',
    role: 'ADMIN',
    permissions: [],
    tenantId: 't1',
    iat: futureNow,
    exp: futureNow + 3600,
    iss: 'fortress-auth-gateway',
    aud: 'fortress-services',
    jti: 'tok_future',
  })).toString('base64url');
  const futureSig = await createHmacSignature(`${header}.${futurePayload}`, MASTER_KEY);
  await assert.rejects(
    async () => verifyToken(`${header}.${futurePayload}.${futureSig}`, MASTER_KEY),
    (err: Error) => err instanceof AuthenticationError && err.message.includes('issued in the future')
  );
});
