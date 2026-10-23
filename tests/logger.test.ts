import test from 'node:test';
import assert from 'node:assert/strict';
import { redactSensitiveData, securityLogger } from '../src/security/logger.ts';

test('Logger: redacts API keys, passwords, and authorization tokens', () => {
  const sensitiveEvent = {
    user: 'mohammed',
    password: 'UnsafePasswordToLog!#99',
    apiKey: 'AKIAIOSFODNN7EXAMPLE',
    nested: {
      clientSecret: 'secret_live_89a0b1c2d3e4f5',
      note: 'User provided Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature',
    },
  };

  const clean = redactSensitiveData(sensitiveEvent);

  assert.equal(clean.password, '[REDACTED]');
  assert.equal(clean.apiKey, '[REDACTED]');
  assert.equal(clean.nested.clientSecret, '[REDACTED]');
  assert.ok(!clean.nested.note.includes('eyJhbGciOiJIUzI1Ni'));
  assert.ok(clean.nested.note.includes('[REDACTED_JWT]'));
});

test('Logger: stores structured audit events in queryable ring-buffer', () => {
  securityLogger.clear();

  securityLogger.log(
    'INJECTION_DETECTED',
    'HIGH',
    'attacker-ip-1',
    '198.51.100.42',
    {
      payload: "1' UNION SELECT username, password FROM users --",
      password: 'AttemptedPasswordCapture',
    }
  );

  const events = securityLogger.getRecentEvents(10);
  assert.equal(events.length, 1);
  const ev = events[0];
  assert.equal(ev.eventType, 'INJECTION_DETECTED');
  assert.equal(ev.severity, 'HIGH');
  assert.equal(ev.sourceIp, '198.51.100.42');
  assert.equal(ev.details.password, '[REDACTED]');
});
