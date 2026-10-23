import test from 'node:test';
import assert from 'node:assert/strict';
import { auditContainerIsolation, assertStrictIsolation, PRODUCTION_HARDENED_PROFILE } from '../src/security/isolation.ts';
import { ValidationError } from '../src/security/errors.ts';

test('Isolation: verifies production hardened container profile complies with CIS & K8s standards', () => {
  const audit = auditContainerIsolation(PRODUCTION_HARDENED_PROFILE);
  assert.equal(audit.isCompliant, true);
  assert.equal(audit.scorePercent, 100);

  // Asserting strict isolation should not throw
  assert.doesNotThrow(() => assertStrictIsolation(PRODUCTION_HARDENED_PROFILE));
});

test('Isolation: flags critical violations when container runs as root (UID 0)', () => {
  const insecureRootProfile = {
    ...PRODUCTION_HARDENED_PROFILE,
    runAsNonRoot: false,
    uid: 0,
    gid: 0,
  };

  const audit = auditContainerIsolation(insecureRootProfile);
  assert.equal(audit.isCompliant, false);
  const rootCheck = audit.checks.find((c) => c.rule === 'NON_ROOT_EXECUTION');
  assert.ok(rootCheck && !rootCheck.passed);

  assert.throws(
    () => assertStrictIsolation(insecureRootProfile),
    ValidationError
  );
});

test('Isolation: flags failure when capabilities are retained or writable rootfs is enabled', () => {
  const insecureCapProfile = {
    ...PRODUCTION_HARDENED_PROFILE,
    dropCapabilities: [], // Retaining default caps
    readOnlyRootFilesystem: false,
  };

  const audit = auditContainerIsolation(insecureCapProfile);
  assert.equal(audit.isCompliant, false);
  const capCheck = audit.checks.find((c) => c.rule === 'CAPABILITIES_DROPPED');
  assert.ok(capCheck && !capCheck.passed);
});
