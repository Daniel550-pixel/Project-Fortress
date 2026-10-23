import test from 'node:test';
import assert from 'node:assert/strict';
import { runSecurityVerificationPipeline } from '../src/security/pipeline.ts';

test('Pipeline: runs full automated security verification suite with zero failures', async () => {
  const report = await runSecurityVerificationPipeline();

  assert.equal(report.status, 'ALL_PASSED');
  assert.equal(report.failedChecks, 0);
  assert.ok(report.totalChecks >= 10);
  assert.equal(report.passedChecks, report.totalChecks);
  assert.ok(report.durationMs >= 0);

  // Verify all categories represented
  const categories = new Set(report.results.map((r) => r.category));
  assert.ok(categories.has('CONFIG'));
  assert.ok(categories.has('INPUT_VALIDATION'));
  assert.ok(categories.has('AUTH'));
  assert.ok(categories.has('LOGGING'));
  assert.ok(categories.has('RATE_LIMIT'));
  assert.ok(categories.has('ISOLATION'));
  assert.ok(categories.has('SUPPLY_CHAIN'));
});
