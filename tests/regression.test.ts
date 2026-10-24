import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectInput, escapeHtml } from '../src/security/sanitizer.ts';
import { redactSensitiveData } from '../src/security/logger.ts';
import { SecretManager, computeSha256 } from '../src/security/secrets.ts';

test('Regression: ReDoS resilience against long repetitive strings', () => {
  // 50,000 characters of repetitive input
  const longPayload = 'A'.repeat(50000);
  const start = Date.now();
  const res = inspectInput(longPayload);
  const elapsed = Date.now() - start;

  assert.equal(res.isClean, true);
  // Must execute under 200ms, proving linear regex performance without catastrophic backtracking
  assert.ok(elapsed < 200, `ReDoS detected: inspection took ${elapsed}ms`);
});

test('Regression: Case-folding and mixed casing in SQL keywords are caught', () => {
  const mixedCaseAttacks = [
    "1' uNiOn SeLeCt 1, 2, 3 --",
    "admin' oR '1'='1",
    "1'; dRoP tAbLe audit_log; --",
  ];

  for (const attack of mixedCaseAttacks) {
    const res = inspectInput(attack);
    assert.equal(res.isClean, false, `Failed to detect mixed-case attack: ${attack}`);
  }
});

test('Regression: Prototype pollution vectors are neutralized', () => {
  const dangerousObject = JSON.parse('{"__proto__": {"polluted": true}}');
  const sanitized = redactSensitiveData(dangerousObject);

  // Assert that global Object prototype was not polluted
  assert.equal((Object.prototype as unknown as { polluted?: boolean }).polluted, undefined);
  assert.ok(sanitized);
});

test('Regression: SecretManager zeroize clears buffer contents in place', () => {
  const sm = new SecretManager();
  const sensitiveBuffer = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  sm.zeroize(sensitiveBuffer);

  for (let i = 0; i < sensitiveBuffer.length; i++) {
    assert.equal(sensitiveBuffer[i], 0);
  }
});

test('Regression: computeSha256 produces exact NIST standard test vectors', () => {
  const enc = new TextEncoder();

  // Test Vector 1: SHA-256("")
  const emptyHash = Buffer.from(computeSha256(enc.encode(''))).toString('hex');
  assert.equal(emptyHash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

  // Test Vector 2: SHA-256("abc")
  const abcHash = Buffer.from(computeSha256(enc.encode('abc'))).toString('hex');
  assert.equal(abcHash, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

  // Test Vector 3: SecretManager deriveKeyBytes matches NIST standard
  const sm = new SecretManager();
  const derived = Buffer.from(sm.deriveKeyBytes('abc')).toString('hex');
  assert.equal(derived, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});
