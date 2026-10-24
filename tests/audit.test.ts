import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { app } from '../server.ts';
import { runSecurityAudit } from '../src/security/audit.ts';

function makeRequest(
  server: http.Server,
  path: string,
  method = 'GET',
  headers: Record<string, string> = {},
  body?: string
): Promise<{ status: number; headers: http.IncomingHttpHeaders; data: any; raw: string }> {
  return new Promise((resolve, reject) => {
    const addr = server.address() as { port: number };
    const req = http.request(
      {
        host: '127.0.0.1',
        port: addr.port,
        path,
        method,
        headers: {
          'Host': '127.0.0.1',
          ...headers,
          ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          let parsed: any = raw;
          try {
            parsed = JSON.parse(raw);
          } catch {
            // Keep as string
          }
          resolve({ status: res.statusCode || 500, headers: res.headers, data: parsed, raw });
        });
      }
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('Security Audit Module: executes full audit suite against app with verifiable evidence', async () => {
  const report = await runSecurityAudit(app);

  assert.ok(report.auditId.startsWith('AUD-'));
  assert.ok(typeof report.timestamp === 'string');
  assert.ok(report.disclaimer.includes('Beperkte lokale audit, geen volledige penetratietest'));
  assert.ok(report.summary.total >= 14);
  assert.ok(report.summary.passed > 0);
  if (report.summary.failed > 0) {
    console.error('FAILED FINDINGS:', JSON.stringify(report.findings.filter((f) => f.status === 'FAIL'), null, 2));
  }
  assert.equal(report.summary.failed, 0);

  // Verify all categories are present in findings
  const categories = new Set(report.findings.map((f) => f.category));
  assert.ok(categories.has('SECURITY_HEADERS'));
  assert.ok(categories.has('STATIC_ALLOWLIST'));
  assert.ok(categories.has('HTTP_METHODS'));
  assert.ok(categories.has('ROUTE_HANDLING'));
  assert.ok(categories.has('SOURCE_EXPOSURE'));

  // Verify findings schema integrity
  for (const finding of report.findings) {
    assert.ok(finding.id.length > 0);
    assert.ok(finding.title.length > 0);
    assert.ok(['PASS', 'FAIL', 'NOT_VERIFIED'].includes(finding.status));
    assert.ok(['INFO', 'LOW', 'MEDIUM', 'HIGH'].includes(finding.severity));
    assert.ok(finding.evidence.length > 0, `Finding ${finding.id} must have concrete evidence`);
    assert.ok(finding.remediation.length > 0, `Finding ${finding.id} must have remediation advice`);
  }

  // Verify specific check results
  const headerCheck = report.findings.find((f) => f.id === 'SEC-HDR-001');
  assert.ok(headerCheck);
  assert.equal(headerCheck.status, 'PASS');
  assert.ok(headerCheck.evidence.includes('nosniff'));

  const cspCheck = report.findings.find((f) => f.id === 'SEC-HDR-005');
  assert.ok(cspCheck);
  assert.equal(cspCheck.status, 'PASS');
  assert.ok(cspCheck.evidence.includes('default-src'));

  const traceCheck = report.findings.find((f) => f.id === 'SEC-MTH-001');
  assert.ok(traceCheck);
  assert.equal(traceCheck.status, 'PASS');

  const sourceCheck = report.findings.find((f) => f.id === 'SEC-EXP-001');
  assert.ok(sourceCheck);
  assert.equal(sourceCheck.status, 'PASS');
});

test('Security Audit Module: unreachable targets result in NOT_VERIFIED status without false PASS claims', async () => {
  // Probe a port where nothing is listening on loopback
  const report = await runSecurityAudit(undefined, {
    targetUrl: 'http://127.0.0.1:59199',
    timeoutMs: 500,
  });

  if (report.summary.passed > 0) {
    console.error('UNEXPECTED PASSING IDS:', report.findings.filter((f) => f.status === 'PASS').map((f) => ({ id: f.id, evidence: f.evidence })));
  }
  assert.ok(report.summary.notVerified > 0, 'Unreachable target checks must be marked NOT_VERIFIED');
  assert.equal(report.summary.passed, 0, 'Unreachable target cannot have any passing checks');

  // Verify that evidence documents unreachability
  const unverifiedFinding = report.findings.find((f) => f.status === 'NOT_VERIFIED');
  assert.ok(unverifiedFinding);
  assert.ok(unverifiedFinding.evidence.includes('unreachable') || unverifiedFinding.evidence.includes('refused') || unverifiedFinding.evidence.includes('timed out'));
});

test('Server API: GET /api/security/audit returns structured security report', async () => {
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    const res = await makeRequest(server, '/api/security/audit');
    assert.equal(res.status, 200);
    assert.ok(res.data.auditId);
    assert.ok(res.data.summary);
    assert.ok(Array.isArray(res.data.findings));
    assert.ok(res.data.summary.total >= 14);
    assert.ok(res.data.summary.passed >= 10);
  } finally {
    server.close();
  }
});

test('Server API: GET /api/security/audit rejects non-loopback external targets (anti-SSRF)', async () => {
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    const res = await makeRequest(server, '/api/security/audit?target=http://169.254.169.254/metadata');
    assert.equal(res.status, 400);
    assert.equal(res.data.error.code, 'INVALID_AUDIT_TARGET');
  } finally {
    server.close();
  }
});

test('Server Protection: rejects TRACE and TRACK HTTP methods with 405 Method Not Allowed', async () => {
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    const traceRes = await makeRequest(server, '/api/health', 'TRACE');
    assert.equal(traceRes.status, 405);
    assert.equal(traceRes.data.error.code, 'METHOD_NOT_ALLOWED');
    assert.equal(traceRes.headers['allow'], 'GET, POST, HEAD, OPTIONS');

    const trackRes = await makeRequest(server, '/api/health', 'TRACK');
    assert.ok(trackRes.status === 405 || trackRes.status === 400);
  } finally {
    server.close();
  }
});

test('Server Protection: blocks direct exposure of internal source files, secrets, and VCS paths', async () => {
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    // 1. Source files
    const serverTsRes = await makeRequest(server, '/server.ts');
    assert.equal(serverTsRes.status, 403);
    assert.equal(serverTsRes.data.error.code, 'FORBIDDEN_FILE_ACCESS');

    const secretsTsRes = await makeRequest(server, '/src/security/secrets.ts');
    assert.equal(secretsTsRes.status, 403);
    assert.equal(secretsTsRes.data.error.code, 'FORBIDDEN_FILE_ACCESS');

    // 2. Secret and VCS files
    const envRes = await makeRequest(server, '/.env');
    assert.equal(envRes.status, 403);
    assert.equal(envRes.data.error.code, 'FORBIDDEN_FILE_ACCESS');

    const gitRes = await makeRequest(server, '/.git/config');
    assert.equal(gitRes.status, 403);
    assert.equal(gitRes.data.error.code, 'FORBIDDEN_FILE_ACCESS');

    const pkgRes = await makeRequest(server, '/package.json');
    assert.equal(pkgRes.status, 403);
    assert.equal(pkgRes.data.error.code, 'FORBIDDEN_FILE_ACCESS');
  } finally {
    server.close();
  }
});

test('Server Protection: unknown API routes return clean 404 JSON without leaking internals', async () => {
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    const res = await makeRequest(server, '/api/nonexistent-endpoint-probe');
    assert.equal(res.status, 404);
    assert.ok(res.headers['content-type']?.includes('application/json'));
    assert.equal(res.data.error.code, 'NOT_FOUND');
    assert.ok(!res.raw.includes('node_modules'));
    assert.ok(!res.raw.includes('stack'));
  } finally {
    server.close();
  }
});
