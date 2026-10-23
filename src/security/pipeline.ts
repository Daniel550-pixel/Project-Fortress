/**
 * Project Fortress — Security Verification Pipeline Engine
 * @license Apache-2.0
 */

import { VerificationCheckResult } from './types.ts';
import { validateAndLoadConfig } from './config.ts';
import { inspectInput, validateOutgoingUrl } from './sanitizer.ts';
import { issueToken, verifyToken, authorizeCapability } from './auth.ts';
import { redactSensitiveData, securityLogger } from './logger.ts';
import { TokenBucketRateLimiter } from './rateLimiter.ts';
import { auditContainerIsolation, PRODUCTION_HARDENED_PROFILE } from './isolation.ts';
import { SecretManager } from './secrets.ts';

export interface PipelineExecutionReport {
  timestamp: string;
  totalChecks: number;
  passedChecks: number;
  failedChecks: number;
  skippedChecks: number;
  status: 'ALL_PASSED' | 'FAILURES_DETECTED';
  durationMs: number;
  results: VerificationCheckResult[];
}

export async function runSecurityVerificationPipeline(): Promise<PipelineExecutionReport> {
  const startTime = Date.now();
  const results: VerificationCheckResult[] = [];

  const runCheck = async (
    id: string,
    category: VerificationCheckResult['category'],
    name: string,
    fn: () => Promise<void> | void
  ) => {
    const checkStart = Date.now();
    try {
      await fn();
      results.push({
        id,
        category,
        name,
        status: 'PASS',
        executionTimeMs: Date.now() - checkStart,
        details: 'Verified successfully against security control policy',
      });
    } catch (err: unknown) {
      results.push({
        id,
        category,
        name,
        status: 'FAIL',
        executionTimeMs: Date.now() - checkStart,
        details: err instanceof Error ? err.message : String(err),
      });
    }
  };

  // 1. CONFIGURATION CHECKS
  await runCheck('SEC-CFG-01', 'CONFIG', 'Reject Weak HMAC Key', () => {
    try {
      validateAndLoadConfig({ FORTRESS_HMAC_SECRET: 'short' });
      throw new Error('Expected validation failure for short HMAC secret');
    } catch (err: unknown) {
      if ((err as Error).message.includes('Expected validation failure')) throw err;
    }
  });

  await runCheck('SEC-CFG-02', 'CONFIG', 'Reject Wildcard CORS in Production', () => {
    try {
      validateAndLoadConfig({
        NODE_ENV: 'production',
        FORTRESS_HMAC_SECRET: 'super-long-secure-key-32chars-min-ok!',
        ALLOWED_ORIGINS: '*',
      });
      throw new Error('Expected wildcard CORS to be rejected');
    } catch (err: unknown) {
      if ((err as Error).message.includes('Expected wildcard')) throw err;
    }
  });

  // 2. INPUT VALIDATION & INJECTION CHECKS
  await runCheck('SEC-INP-01', 'INPUT_VALIDATION', 'Detect and Block SQL Injection Payloads', () => {
    const payload = "admin' OR '1'='1' UNION SELECT username, password_hash FROM users--";
    const res = inspectInput(payload);
    if (res.isClean) throw new Error('SQL Injection payload bypassed detection');
    if (!res.detectedThreats.some((t) => t.type === 'SQLI')) throw new Error('Failed to classify as SQLI');
  });

  await runCheck('SEC-INP-02', 'INPUT_VALIDATION', 'Detect NoSQL Operator Injections', () => {
    const payload = '{"$where: function() { return true; }}"}';
    const res = inspectInput(payload);
    if (res.isClean) throw new Error('NoSQL Injection bypassed detection');
  });

  await runCheck('SEC-INP-03', 'INPUT_VALIDATION', 'Detect Command Injection Attempts', () => {
    const payload = 'file.txt; cat /etc/passwd | bash';
    const res = inspectInput(payload);
    if (res.isClean) throw new Error('Command Injection payload bypassed detection');
  });

  await runCheck('SEC-INP-04', 'INPUT_VALIDATION', 'Detect Path Traversal & Null Bytes', () => {
    const payload = '../../../../etc/passwd%00.png';
    const res = inspectInput(payload);
    if (res.isClean) throw new Error('Path Traversal payload bypassed detection');
  });

  await runCheck('SEC-INP-05', 'INPUT_VALIDATION', 'SSRF Guard Blocks RFC-1918 & Cloud Metadata', () => {
    const badTargets = [
      'http://127.0.0.1:8080/admin',
      'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.5/internal/metrics',
      'http://192.168.1.1/router',
      'ftp://example.com/file',
    ];
    for (const target of badTargets) {
      const check = validateOutgoingUrl(target);
      if (check.isValid) throw new Error(`SSRF target was not blocked: ${target}`);
    }
    const goodCheck = validateOutgoingUrl('https://api.github.com/repos');
    if (!goodCheck.isValid) throw new Error('Legitimate public HTTPS URL was incorrectly blocked');
  });

  // 3. AUTHENTICATION & RBAC CHECKS
  const testSecret = 'test-suite-cryptographic-master-key-32chars!';
  let issuedToken = '';

  await runCheck('SEC-AUTH-01', 'AUTH', 'Issue & Cryptographically Verify Bearer Token', async () => {
    issuedToken = await issueToken(
      { id: 'usr-123', username: 'sec-admin', role: 'ADMIN', tenantId: 'tenant-uae' },
      testSecret,
      3600
    );
    const verified = await verifyToken(issuedToken, testSecret);
    if (verified.username !== 'sec-admin' || verified.role !== 'ADMIN') {
      throw new Error('Token claims mismatch upon verification');
    }
  });

  await runCheck('SEC-AUTH-02', 'AUTH', 'Reject Tampered Token Signature', async () => {
    const tampered = issuedToken.slice(0, -6) + 'abc123';
    try {
      await verifyToken(tampered, testSecret);
      throw new Error('Tampered token unexpectedly passed verification');
    } catch (err: unknown) {
      if ((err as Error).message.includes('unexpectedly passed')) throw err;
    }
  });

  await runCheck('SEC-AUTH-03', 'AUTH', 'Enforce Least-Privilege Capability Matrix', async () => {
    const auditorToken = await issueToken(
      { id: 'usr-audit', username: 'auditor', role: 'AUDIT', tenantId: 'tenant-uae' },
      testSecret,
      3600
    );
    const payload = await verifyToken(auditorToken, testSecret);
    // AUDIT can read telemetry
    authorizeCapability(payload, 'read:telemetry');
    // AUDIT cannot rotate keys
    try {
      authorizeCapability(payload, 'rotate:keys');
      throw new Error('Audit role allowed unauthorized capability rotate:keys');
    } catch (err: unknown) {
      if ((err as Error).message.includes('Audit role allowed')) throw err;
    }
  });

  // 4. SANITIZED LOGGING & SECRET REDACTION
  await runCheck('SEC-LOG-01', 'LOGGING', 'Deterministic Redaction of API Keys & Passwords', () => {
    const raw = {
      password: 'SuperSecretPassword123!',
      apiKey: 'AKIAIOSFODNN7EXAMPLE',
      rawText: 'Client authorization header: Bearer mySecretToken1234567890',
    };
    const redacted = redactSensitiveData(raw);
    if (redacted.password !== '[REDACTED]') throw new Error('Password was not redacted');
    if (redacted.rawText.includes('mySecretToken1234567890')) throw new Error('Bearer token leaked in text');
    if (redacted.rawText.includes('AKIAIOSFODNN7EXAMPLE')) throw new Error('AWS Key leaked in text');
  });

  // 5. RATE LIMITING CHECKS
  await runCheck('SEC-RAT-01', 'RATE_LIMIT', 'Token Bucket Depletion and Throttling', () => {
    const limiter = new TokenBucketRateLimiter(5, 60000);
    for (let i = 0; i < 5; i++) {
      const res = limiter.consume('client-test-ip');
      if (!res.allowed) throw new Error(`Request ${i + 1} was prematurely throttled`);
    }
    const sixth = limiter.consume('client-test-ip');
    if (sixth.allowed) throw new Error('Sixth request exceeded capacity but was allowed');
  });

  // 6. RUNTIME ISOLATION CHECKS
  await runCheck('SEC-ISO-01', 'ISOLATION', 'Audit Production Hardened Profile Compliance', () => {
    const audit = auditContainerIsolation(PRODUCTION_HARDENED_PROFILE);
    if (!audit.isCompliant) throw new Error(`Production profile failed compliance: score ${audit.scorePercent}%`);
    if (audit.scorePercent < 100) throw new Error('Production profile did not achieve 100% compliance score');
  });

  // 7. SECRETS ENVELOPE ENCRYPTION & ROTATION
  await runCheck('SEC-SEC-01', 'SUPPLY_CHAIN', 'Envelope Encryption and Key Rotation Verification', async () => {
    const sm = new SecretManager('k1', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
    const plaintext = 'Sovereign_UAE_Critical_Infrastructure_Key_2026';
    const env = await sm.encryptSecret(plaintext);
    const decrypted = await sm.decryptSecret(env);
    if (decrypted !== plaintext) throw new Error('Decrypted secret does not match original plaintext');

    // Key rotation
    sm.rotateKey('k2', 'new-seed-for-q1-2027-cryptographic-rotation!');
    const env2 = await sm.encryptSecret('NewSecretUnderK2');
    const dec2 = await sm.decryptSecret(env2);
    if (dec2 !== 'NewSecretUnderK2') throw new Error('Decryption under rotated key failed');
    // Verify backwards compatibility for k1
    const oldDec = await sm.decryptSecret(env);
    if (oldDec !== plaintext) throw new Error('Backwards compatibility for rotated key failed');
  });

  const passed = results.filter((r) => r.status === 'PASS').length;
  const failed = results.filter((r) => r.status === 'FAIL').length;
  const skipped = results.filter((r) => r.status === 'SKIPPED').length;

  return {
    timestamp: new Date().toISOString(),
    totalChecks: results.length,
    passedChecks: passed,
    failedChecks: failed,
    skippedChecks: skipped,
    status: failed === 0 ? 'ALL_PASSED' : 'FAILURES_DETECTED',
    durationMs: Date.now() - startTime,
    results,
  };
}
