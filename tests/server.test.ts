import test from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../server.ts';
import http from 'node:http';

function makeRequest(
  server: http.Server,
  path: string,
  method = 'GET',
  body?: Record<string, unknown>
): Promise<{ status: number; headers: http.IncomingHttpHeaders; data: any }> {
  return new Promise((resolve, reject) => {
    const addr = server.address() as { port: number };
    const payload = body ? JSON.stringify(body) : undefined;
    const req = http.request(
      {
        host: '127.0.0.1',
        port: addr.port,
        path,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
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
          resolve({ status: res.statusCode || 500, headers: res.headers, data: parsed });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

test('Server: /api/health returns operational status without leaking sensitive information', async () => {
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    const res = await makeRequest(server, '/api/health');
    assert.equal(res.status, 200);
    assert.equal(res.data.status, 'HEALTHY');
    assert.ok(typeof res.data.timestamp === 'string');
    assert.ok(typeof res.data.uptimeSeconds === 'number');

    // Strict non-disclosure assertions
    assert.equal(res.data.environment, undefined);
    assert.equal(res.data.hmacSecret, undefined);
    assert.equal(res.data.nodeVersion, undefined);
    assert.equal(res.data.paths, undefined);

    // Verify security headers
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN');
    assert.ok(String(res.headers['content-security-policy']).includes("default-src 'self'"));
  } finally {
    server.close();
  }
});

test('Server: /api/sanitize detects injection and SSRF payloads', async () => {
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    const res = await makeRequest(server, '/api/sanitize', 'POST', {
      input: "admin' OR '1'='1' --",
      url: 'http://169.254.169.254/latest/meta-data/',
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.inputInspection.isClean, false);
    assert.equal(res.data.urlValidation.isValid, false);
    assert.ok(String(res.data.urlValidation.reason).includes('Cloud Instance Metadata'));
  } finally {
    server.close();
  }
});
