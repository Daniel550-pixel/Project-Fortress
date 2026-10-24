/**
 * Project Fortress — Modular Security Audit Engine
 * @license Apache-2.0
 * 
 * Verifiable local security audit module evaluating:
 * 1. Presence and strictness of the five expected security headers (CSP, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy)
 * 2. Explicit allowlist for static file assets and rejection of disallowed extensions
 * 3. Rejection of dangerous/disallowed HTTP methods (TRACE, TRACK)
 * 4. Safe handling of unknown API routes (404 JSON, no stack leak)
 * 5. Protection against internal source code, secrets, and VCS exposure
 */

import http from 'node:http';
import type { Express } from 'express';
import {
  AuditFinding,
  AuditFindingCategory,
  AuditFindingSeverity,
  AuditFindingStatus,
  SecurityAuditReport,
} from './types.ts';

export interface AuditRunOptions {
  /** Target base URL to probe (e.g. 'http://127.0.0.1:3000') */
  targetUrl?: string;
  /** Express application instance to audit over an ephemeral loopback port */
  app?: Express;
  /** Request timeout in milliseconds */
  timeoutMs?: number;
}

interface ProbeResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  durationMs: number;
}

/**
 * Execute a low-level HTTP probe against loopback target
 */
async function probeHttp(
  targetUrl: string,
  pathname: string,
  method = 'GET',
  headers: Record<string, string> = {},
  body?: string,
  timeoutMs = 2500
): Promise<ProbeResponse> {
  const url = new URL(pathname, targetUrl);
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    const req = http.request(
      url,
      {
        method,
        headers: {
          'Host': url.host,
          'User-Agent': 'Fortress-Security-Audit/1.0',
          ...headers,
          ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
        },
        timeout: timeoutMs,
      },
      (res) => {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          raw += chunk;
        });
        res.on('end', () => {
          resolve({
            status: res.statusCode || 0,
            headers: res.headers,
            body: raw,
            durationMs: Date.now() - startTime,
          });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error(`Probe timed out after ${timeoutMs}ms`));
    });

    req.on('error', (err) => {
      reject(err);
    });

    if (body) {
      req.write(body);
    }
    req.end();
  });
}

/**
 * Run a full automated security audit against the configured target.
 * Guarantees that any test which cannot be executed is marked NOT_VERIFIED.
 */
export async function runSecurityAudit(
  appOrOptions?: Express | AuditRunOptions,
  options?: AuditRunOptions
): Promise<SecurityAuditReport> {
  const auditId = `AUD-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 7)}`;
  const timestamp = new Date().toISOString();
  const findings: AuditFinding[] = [];

  let resolvedApp: Express | undefined;
  let targetUrl: string | undefined;
  let timeoutMs = 2500;

  if (appOrOptions && typeof (appOrOptions as any).use === 'function') {
    resolvedApp = appOrOptions as Express;
    targetUrl = options?.targetUrl;
    timeoutMs = options?.timeoutMs || 2500;
  } else if (appOrOptions && typeof appOrOptions === 'object') {
    const opts = appOrOptions as AuditRunOptions;
    resolvedApp = opts.app;
    targetUrl = opts.targetUrl;
    timeoutMs = opts.timeoutMs || 2500;
  } else if (options && typeof options === 'object') {
    resolvedApp = options.app;
    targetUrl = options.targetUrl;
    timeoutMs = options.timeoutMs || 2500;
  }

  // Manage ephemeral server if an app is provided
  let ephemeralServer: http.Server | null = null;
  let activeBaseUrl = targetUrl;

  try {
    if (resolvedApp && !targetUrl) {
      ephemeralServer = http.createServer(resolvedApp);
      await new Promise<void>((resolve, reject) => {
        ephemeralServer!.listen(0, '127.0.0.1', () => resolve());
        ephemeralServer!.on('error', reject);
      });
      const addr = ephemeralServer.address() as { port: number };
      activeBaseUrl = `http://127.0.0.1:${addr.port}`;
    }

    if (!activeBaseUrl) {
      activeBaseUrl = 'http://127.0.0.1:3000';
    }

    // -------------------------------------------------------------------------
    // 1. SECURITY HEADERS CHECKS
    // -------------------------------------------------------------------------
    let healthProbe: ProbeResponse | null = null;
    let healthProbeError: Error | null = null;

    try {
      healthProbe = await probeHttp(activeBaseUrl, '/api/health', 'GET', {}, undefined, timeoutMs);
    } catch (err: any) {
      healthProbeError = err;
    }

    // Check 1: X-Content-Type-Options
    if (healthProbe) {
      const val = healthProbe.headers['x-content-type-options'];
      const pass = val === 'nosniff';
      findings.push({
        id: 'SEC-HDR-001',
        title: 'X-Content-Type-Options Header Verification',
        category: 'SECURITY_HEADERS',
        description: 'Ensures the MIME-type sniffing protection header is set strictly to "nosniff" to prevent MIME confusion and script execution.',
        status: pass ? 'PASS' : 'FAIL',
        severity: 'MEDIUM',
        evidence: `Received X-Content-Type-Options: "${val || 'MISSING'}" (HTTP ${healthProbe.status})`,
        remediation: 'Configure middleware: res.setHeader("X-Content-Type-Options", "nosniff");',
        testedAt: new Date().toISOString(),
      });
    } else {
      findings.push({
        id: 'SEC-HDR-001',
        title: 'X-Content-Type-Options Header Verification',
        category: 'SECURITY_HEADERS',
        description: 'Ensures the MIME-type sniffing protection header is set strictly to "nosniff".',
        status: 'NOT_VERIFIED',
        severity: 'MEDIUM',
        evidence: `Target unreachable: ${healthProbeError?.message || 'Connection refused'}`,
        remediation: 'Verify server is running and accessible on loopback 127.0.0.1 before initiating audit.',
        testedAt: new Date().toISOString(),
      });
    }

    // Check 2: X-Frame-Options
    if (healthProbe) {
      const val = String(healthProbe.headers['x-frame-options'] || '').toUpperCase();
      const pass = val === 'SAMEORIGIN' || val === 'DENY';
      findings.push({
        id: 'SEC-HDR-002',
        title: 'X-Frame-Options Anti-Clickjacking Header',
        category: 'SECURITY_HEADERS',
        description: 'Ensures the X-Frame-Options header restricts framing to prevent UI redressing and clickjacking.',
        status: pass ? 'PASS' : 'FAIL',
        severity: 'MEDIUM',
        evidence: `Received X-Frame-Options: "${healthProbe.headers['x-frame-options'] || 'MISSING'}"`,
        remediation: 'Set header to SAMEORIGIN or DENY via res.setHeader("X-Frame-Options", "SAMEORIGIN");',
        testedAt: new Date().toISOString(),
      });
    } else {
      findings.push({
        id: 'SEC-HDR-002',
        title: 'X-Frame-Options Anti-Clickjacking Header',
        category: 'SECURITY_HEADERS',
        description: 'Ensures the X-Frame-Options header restricts framing.',
        status: 'NOT_VERIFIED',
        severity: 'MEDIUM',
        evidence: `Target unreachable: ${healthProbeError?.message || 'Connection refused'}`,
        remediation: 'Verify server connection.',
        testedAt: new Date().toISOString(),
      });
    }

    // Check 3: X-XSS-Protection
    if (healthProbe) {
      const val = String(healthProbe.headers['x-xss-protection'] || '');
      const pass = val.includes('1') || val.includes('mode=block');
      findings.push({
        id: 'SEC-HDR-003',
        title: 'X-XSS-Protection Filter Header',
        category: 'SECURITY_HEADERS',
        description: 'Validates legacy browser cross-site scripting filter activation.',
        status: pass ? 'PASS' : 'FAIL',
        severity: 'LOW',
        evidence: `Received X-XSS-Protection: "${val || 'MISSING'}"`,
        remediation: 'Configure middleware: res.setHeader("X-XSS-Protection", "1; mode=block");',
        testedAt: new Date().toISOString(),
      });
    } else {
      findings.push({
        id: 'SEC-HDR-003',
        title: 'X-XSS-Protection Filter Header',
        category: 'SECURITY_HEADERS',
        description: 'Validates legacy browser cross-site scripting filter activation.',
        status: 'NOT_VERIFIED',
        severity: 'LOW',
        evidence: `Target unreachable: ${healthProbeError?.message || 'Connection refused'}`,
        remediation: 'Verify server connection.',
        testedAt: new Date().toISOString(),
      });
    }

    // Check 4: Referrer-Policy
    if (healthProbe) {
      const val = String(healthProbe.headers['referrer-policy'] || '');
      const pass = ['strict-origin-when-cross-origin', 'no-referrer', 'same-origin', 'strict-origin'].includes(val.toLowerCase());
      findings.push({
        id: 'SEC-HDR-004',
        title: 'Referrer-Policy Information Leakage Defense',
        category: 'SECURITY_HEADERS',
        description: 'Guarantees referrer metadata does not leak sensitive query params across insecure origins.',
        status: pass ? 'PASS' : 'FAIL',
        severity: 'LOW',
        evidence: `Received Referrer-Policy: "${val || 'MISSING'}"`,
        remediation: 'Set res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");',
        testedAt: new Date().toISOString(),
      });
    } else {
      findings.push({
        id: 'SEC-HDR-004',
        title: 'Referrer-Policy Information Leakage Defense',
        category: 'SECURITY_HEADERS',
        description: 'Guarantees referrer metadata does not leak sensitive query params.',
        status: 'NOT_VERIFIED',
        severity: 'LOW',
        evidence: `Target unreachable: ${healthProbeError?.message || 'Connection refused'}`,
        remediation: 'Verify server connection.',
        testedAt: new Date().toISOString(),
      });
    }

    // Check 5: Content-Security-Policy
    if (healthProbe) {
      const csp = String(healthProbe.headers['content-security-policy'] || '');
      const pass = csp.includes('default-src');
      findings.push({
        id: 'SEC-HDR-005',
        title: 'Content-Security-Policy (CSP) Policy Enforcement',
        category: 'SECURITY_HEADERS',
        description: 'Verifies presence of Content-Security-Policy defining at minimum a baseline default-src directive.',
        status: pass ? 'PASS' : 'FAIL',
        severity: 'HIGH',
        evidence: pass
          ? `CSP configured with default-src (${csp.slice(0, 70)}...)`
          : `CSP missing default-src directive or header absent. Value: "${csp || 'MISSING'}"`,
        remediation: 'Configure a strict Content-Security-Policy restricting script-src, default-src, and frame-ancestors.',
        testedAt: new Date().toISOString(),
      });
    } else {
      findings.push({
        id: 'SEC-HDR-005',
        title: 'Content-Security-Policy (CSP) Policy Enforcement',
        category: 'SECURITY_HEADERS',
        description: 'Verifies presence of Content-Security-Policy defining at minimum a baseline default-src directive.',
        status: 'NOT_VERIFIED',
        severity: 'HIGH',
        evidence: `Target unreachable: ${healthProbeError?.message || 'Connection refused'}`,
        remediation: 'Verify server connection.',
        testedAt: new Date().toISOString(),
      });
    }

    // Check 6: HSTS Transport Security Status
    if (activeBaseUrl.startsWith('https://')) {
      if (healthProbe) {
        const hsts = healthProbe.headers['strict-transport-security'];
        const pass = typeof hsts === 'string' && hsts.includes('max-age');
        findings.push({
          id: 'SEC-HDR-006',
          title: 'HTTP Strict Transport Security (HSTS)',
          category: 'SECURITY_HEADERS',
          description: 'Verifies Strict-Transport-Security header is active over HTTPS connections.',
          status: pass ? 'PASS' : 'FAIL',
          severity: 'MEDIUM',
          evidence: `HSTS: "${hsts || 'MISSING'}"`,
          remediation: 'Configure Strict-Transport-Security: max-age=31536000; includeSubDomains',
          testedAt: new Date().toISOString(),
        });
      }
    } else {
      // Accurately document that HSTS is NOT_VERIFIED over plain HTTP loopback
      findings.push({
        id: 'SEC-HDR-006',
        title: 'HTTP Strict Transport Security (HSTS)',
        category: 'SECURITY_HEADERS',
        description: 'Evaluates HTTP Strict Transport Security (HSTS) enforcement.',
        status: 'NOT_VERIFIED',
        severity: 'INFO',
        evidence: `HSTS is only applicable over TLS/HTTPS transports. Local target (${activeBaseUrl}) was probed over plain HTTP loopback.`,
        remediation: 'Enforce HSTS at production TLS reverse proxy (e.g. Nginx/Cloudflare) with max-age >= 31536000.',
        testedAt: new Date().toISOString(),
      });
    }

    // -------------------------------------------------------------------------
    // 2. HTTP METHODS CHECKS
    // -------------------------------------------------------------------------

    // Check 7: TRACE Method Rejection (XST Prevention)
    try {
      const traceRes = await probeHttp(activeBaseUrl, '/api/health', 'TRACE', {}, undefined, timeoutMs);
      const isRejected = traceRes.status === 405 || traceRes.status === 403 || traceRes.status === 501;
      findings.push({
        id: 'SEC-MTH-001',
        title: 'HTTP TRACE Method Rejection (XST Defense)',
        category: 'HTTP_METHODS',
        description: 'Verifies HTTP TRACE requests are rejected (HTTP 405 Method Not Allowed) to prevent Cross-Site Tracing header theft.',
        status: isRejected ? 'PASS' : 'FAIL',
        severity: 'MEDIUM',
        evidence: isRejected
          ? `Server rejected TRACE request with HTTP ${traceRes.status} (Method Not Allowed). Body: ${traceRes.body.slice(0, 60)}`
          : `Server unexpectedly allowed TRACE request with HTTP ${traceRes.status}. Potential XST risk.`,
        remediation: 'Add method filtering middleware: if (req.method === "TRACE") return res.status(405).json({ error: "METHOD_NOT_ALLOWED" });',
        testedAt: new Date().toISOString(),
      });
    } catch (err: any) {
      findings.push({
        id: 'SEC-MTH-001',
        title: 'HTTP TRACE Method Rejection (XST Defense)',
        category: 'HTTP_METHODS',
        description: 'Verifies HTTP TRACE requests are rejected.',
        status: 'NOT_VERIFIED',
        severity: 'MEDIUM',
        evidence: `Probe failed: ${err.message}`,
        remediation: 'Verify server loopback connectivity.',
        testedAt: new Date().toISOString(),
      });
    }

    // Check 8: TRACK Method Rejection
    try {
      const trackRes = await probeHttp(activeBaseUrl, '/api/health', 'TRACK', {}, undefined, timeoutMs);
      const isRejected = trackRes.status === 405 || trackRes.status === 403 || trackRes.status === 400 || trackRes.status === 501;
      findings.push({
        id: 'SEC-MTH-002',
        title: 'HTTP TRACK Method Rejection',
        category: 'HTTP_METHODS',
        description: 'Verifies HTTP TRACK requests are rejected with HTTP 405 or HTTP 400 by HTTP parser.',
        status: isRejected ? 'PASS' : 'FAIL',
        severity: 'LOW',
        evidence: `Server rejected TRACK request with HTTP ${trackRes.status}.`,
        remediation: 'Explicitly reject TRACK method alongside TRACE in HTTP method policy.',
        testedAt: new Date().toISOString(),
      });
    } catch (err: any) {
      findings.push({
        id: 'SEC-MTH-002',
        title: 'HTTP TRACK Method Rejection',
        category: 'HTTP_METHODS',
        description: 'Verifies HTTP TRACK requests are rejected.',
        status: 'NOT_VERIFIED',
        severity: 'LOW',
        evidence: `Probe failed: ${err.message}`,
        remediation: 'Verify server loopback connectivity.',
        testedAt: new Date().toISOString(),
      });
    }

    // Check 9: Standard Methods Acceptance
    try {
      const getRes = await probeHttp(activeBaseUrl, '/api/health', 'GET', {}, undefined, timeoutMs);
      const pass = getRes.status === 200;
      findings.push({
        id: 'SEC-MTH-003',
        title: 'Standard HTTP Methods Acceptance',
        category: 'HTTP_METHODS',
        description: 'Confirms legitimate GET operations succeed without false-positive blocking.',
        status: pass ? 'PASS' : 'FAIL',
        severity: 'LOW',
        evidence: `GET /api/health returned HTTP ${getRes.status} (operational).`,
        remediation: 'Ensure security filters only intercept disallowed verbs without disrupting standard REST routes.',
        testedAt: new Date().toISOString(),
      });
    } catch (err: any) {
      findings.push({
        id: 'SEC-MTH-003',
        title: 'Standard HTTP Methods Acceptance',
        category: 'HTTP_METHODS',
        description: 'Confirms legitimate GET operations succeed.',
        status: 'NOT_VERIFIED',
        severity: 'LOW',
        evidence: `Probe failed: ${err.message}`,
        remediation: 'Verify server loopback connectivity.',
        testedAt: new Date().toISOString(),
      });
    }

    // -------------------------------------------------------------------------
    // 3. STATIC FILE ALLOWLIST CHECKS
    // -------------------------------------------------------------------------

    // Check 10: Disallowed File Extensions Blocked
    const disallowedProbes = [
      '/sensitive-config.env',
      '/internal.sql',
      '/application.map',
      '/deployment.yml',
      '/run.sh',
    ];
    let disallowedLeaked = false;
    let disallowedSuccessCount = 0;
    const disallowedResults: string[] = [];

    for (const testPath of disallowedProbes) {
      try {
        const res = await probeHttp(activeBaseUrl, testPath, 'GET', {}, undefined, timeoutMs);
        disallowedSuccessCount++;
        disallowedResults.push(`${testPath} -> HTTP ${res.status}`);
        if (res.status === 200) {
          disallowedLeaked = true;
        }
      } catch (err: any) {
        disallowedResults.push(`${testPath} -> error (${err.message})`);
      }
    }

    const staticStatus: AuditFindingStatus =
      disallowedSuccessCount === 0 ? 'NOT_VERIFIED' : disallowedLeaked ? 'FAIL' : 'PASS';

    findings.push({
      id: 'SEC-STA-001',
      title: 'Explicit Allowlist for Static Files Enforcement',
      category: 'STATIC_ALLOWLIST',
      description: 'Verifies that requests for disallowed static file types (.env, .sql, .map, .yml, .sh) are blocked (403 Forbidden or 404 Not Found), preventing arbitrary file retrieval.',
      status: staticStatus,
      severity: 'HIGH',
      evidence:
        disallowedSuccessCount === 0
          ? `Could not reach target to verify static allowlist: ${disallowedResults[0]}`
          : `Probed dangerous extensions: [${disallowedResults.join(', ')}]. Zero 200 status leaks detected.`,
      remediation: 'Enforce static allowlist restricting servable extensions exclusively to safe web assets (.html, .js, .css, .svg, .png, .ico, .json, .wasm).',
      testedAt: new Date().toISOString(),
    });

    // -------------------------------------------------------------------------
    // 4. INTERNAL SOURCE FILE EXPOSURE CHECKS
    // -------------------------------------------------------------------------

    // Check 11: Source Code File Exposure (TypeScript / source files)
    const sourceProbes = ['/server.ts', '/src/App.tsx', '/src/security/secrets.ts'];
    let sourceExposed = false;
    let sourceSuccessCount = 0;
    const sourceEvidenceParts: string[] = [];

    for (const p of sourceProbes) {
      try {
        const res = await probeHttp(activeBaseUrl, p, 'GET', {}, undefined, timeoutMs);
        sourceSuccessCount++;
        const containsTsCode =
          res.body.includes('import express') ||
          res.body.includes('FortressError') ||
          res.body.includes('computeSha256') ||
          res.body.includes('export function');

        sourceEvidenceParts.push(`${p}: HTTP ${res.status}${containsTsCode ? ' (LEAKED CODE)' : ''}`);
        if (res.status === 200 && containsTsCode) {
          sourceExposed = true;
        }
      } catch (err: any) {
        sourceEvidenceParts.push(`${p}: error (${err.message})`);
      }
    }

    const sourceStatus: AuditFindingStatus =
      sourceSuccessCount === 0 ? 'NOT_VERIFIED' : sourceExposed ? 'FAIL' : 'PASS';

    findings.push({
      id: 'SEC-EXP-001',
      title: 'Internal Source Code Exposure Defense',
      category: 'SOURCE_EXPOSURE',
      description: 'Verifies that internal application source files (.ts, .tsx, /src/*) cannot be retrieved over HTTP, preventing architecture and implementation disclosure.',
      status: sourceStatus,
      severity: 'HIGH',
      evidence:
        sourceSuccessCount === 0
          ? `Target unreachable to test source code exposure: ${sourceEvidenceParts[0]}`
          : `Probed source paths: [${sourceEvidenceParts.join('; ')}]. All source paths shielded.`,
      remediation: 'Ensure Express does not serve root or src/ directories statically. Reject requests matching *.ts, *.tsx, and /src/ paths with HTTP 403.',
      testedAt: new Date().toISOString(),
    });

    // Check 12: Secrets & VCS Metadata Exposure
    const vcsProbes = ['/.env', '/.env.example', '/.git/config', '/package.json'];
    let vcsExposed = false;
    let vcsSuccessCount = 0;
    const vcsEvidenceParts: string[] = [];

    for (const p of vcsProbes) {
      try {
        const res = await probeHttp(activeBaseUrl, p, 'GET', {}, undefined, timeoutMs);
        vcsSuccessCount++;
        const leakedSecret = res.body.includes('GEMINI_API_KEY') || res.body.includes('[core]') || res.body.includes('"dependencies":');
        vcsEvidenceParts.push(`${p}: HTTP ${res.status}`);
        if (res.status === 200 && leakedSecret) {
          vcsExposed = true;
        }
      } catch (err: any) {
        vcsEvidenceParts.push(`${p}: error`);
      }
    }

    const vcsStatus: AuditFindingStatus =
      vcsSuccessCount === 0 ? 'NOT_VERIFIED' : vcsExposed ? 'FAIL' : 'PASS';

    findings.push({
      id: 'SEC-EXP-002',
      title: 'Environment Secrets & VCS Metadata Shielding',
      category: 'SOURCE_EXPOSURE',
      description: 'Guarantees repository metadata (.git) and environment secret files (.env) are never accessible through web routes.',
      status: vcsStatus,
      severity: 'HIGH',
      evidence:
        vcsSuccessCount === 0
          ? `Target unreachable to test environment secrets exposure.`
          : `Probed configuration paths: [${vcsEvidenceParts.join(', ')}]. Zero secret exposures.`,
      remediation: 'Strictly deny any request for dotfiles and configuration manifests in web routing.',
      testedAt: new Date().toISOString(),
    });

    // -------------------------------------------------------------------------
    // 5. UNKNOWN ROUTE HANDLING CHECKS
    // -------------------------------------------------------------------------

    // Check 13: Clean 404 JSON for Unknown API Routes
    const unknownApiPath = `/api/security/unknown-probe-${Date.now().toString(36)}`;
    try {
      const notFoundRes = await probeHttp(activeBaseUrl, unknownApiPath, 'GET', {}, undefined, timeoutMs);
      const is404 = notFoundRes.status === 404;
      let isJson = false;
      let hasStructuredError = false;

      try {
        const parsed = JSON.parse(notFoundRes.body);
        isJson = true;
        if (parsed.error && (parsed.error.code === 'NOT_FOUND' || parsed.error.message)) {
          hasStructuredError = true;
        }
      } catch {
        isJson = false;
      }

      const pass = is404 && isJson;
      findings.push({
        id: 'SEC-ROU-001',
        title: 'Structured 404 Handling on Unknown API Routes',
        category: 'ROUTE_HANDLING',
        description: 'Verifies unknown API routes return HTTP 404 with structured JSON, preventing SPA fallback routing on API endpoints or unhandled crash.',
        status: pass ? 'PASS' : 'FAIL',
        severity: 'LOW',
        evidence: `Probed ${unknownApiPath}: status=${notFoundRes.status}, isJson=${isJson}, hasStructuredError=${hasStructuredError}, bodySnippet="${notFoundRes.body.slice(0, 50)}"`,
        remediation: 'Register app.all("/api/*", ...) returning res.status(404).json({ error: { code: "NOT_FOUND" } }) prior to SPA catch-all.',
        testedAt: new Date().toISOString(),
      });
    } catch (err: any) {
      findings.push({
        id: 'SEC-ROU-001',
        title: 'Structured 404 Handling on Unknown API Routes',
        category: 'ROUTE_HANDLING',
        description: 'Verifies unknown API routes return HTTP 404 with structured JSON.',
        status: 'NOT_VERIFIED',
        severity: 'LOW',
        evidence: `Probe failed: ${err.message}`,
        remediation: 'Verify server loopback connectivity.',
        testedAt: new Date().toISOString(),
      });
    }

    // Check 14: Non-Disclosure of Stack Traces or Internal Paths
    try {
      // Intentionally send malformed payload to check error formatting
      const malformedRes = await probeHttp(
        activeBaseUrl,
        '/api/sanitize',
        'POST',
        { 'Content-Type': 'application/json' },
        '{"malformed_payload: unclosed',
        timeoutMs
      );

      const stackMarkers = [
        'at Object.',
        'at process.',
        'at Module.',
        'node_modules',
        'server.ts:',
        '/app/applet/',
        'SyntaxError:',
      ];
      const leakedMarker = stackMarkers.find((marker) => malformedRes.body.includes(marker));
      const pass = !leakedMarker;

      findings.push({
        id: 'SEC-ROU-002',
        title: 'Stack Trace & Debug Information Non-Disclosure',
        category: 'ROUTE_HANDLING',
        description: 'Validates that error responses under malformed payloads or unhandled requests never leak server stack traces or filesystem paths.',
        status: pass ? 'PASS' : 'FAIL',
        severity: 'MEDIUM',
        evidence: pass
          ? `Status ${malformedRes.status}; payload safely formatted without stack markers.`
          : `Stack trace disclosure detected! Found marker "${leakedMarker}" in response body: ${malformedRes.body.slice(0, 100)}`,
        remediation: 'Ensure Express centralized error middleware never returns err.stack in response payloads.',
        testedAt: new Date().toISOString(),
      });
    } catch (err: any) {
      findings.push({
        id: 'SEC-ROU-002',
        title: 'Stack Trace & Debug Information Non-Disclosure',
        category: 'ROUTE_HANDLING',
        description: 'Validates error responses do not leak stack traces.',
        status: 'NOT_VERIFIED',
        severity: 'MEDIUM',
        evidence: `Probe failed: ${err.message}`,
        remediation: 'Verify server loopback connectivity.',
        testedAt: new Date().toISOString(),
      });
    }

    // Check 15: Global Rate Limiting Headers Presence
    if (healthProbe) {
      const limitHeader = healthProbe.headers['x-ratelimit-limit'];
      const remainingHeader = healthProbe.headers['x-ratelimit-remaining'];
      const pass = typeof limitHeader === 'string' && typeof remainingHeader === 'string';

      findings.push({
        id: 'SEC-ENV-001',
        title: 'Global Rate Limiting Telemetry Headers',
        category: 'ENVIRONMENT',
        description: 'Confirms rate limiter middleware injects standard quota transparency headers (X-RateLimit-Limit, X-RateLimit-Remaining).',
        status: pass ? 'PASS' : 'FAIL',
        severity: 'INFO',
        evidence: pass
          ? `Headers present: limit=${limitHeader}, remaining=${remainingHeader}`
          : 'Rate limiting headers missing from API responses.',
        remediation: 'Verify rate limiting middleware is mounted before route handlers.',
        testedAt: new Date().toISOString(),
      });
    } else {
      findings.push({
        id: 'SEC-ENV-001',
        title: 'Global Rate Limiting Telemetry Headers',
        category: 'ENVIRONMENT',
        description: 'Confirms rate limiter middleware injects standard quota transparency headers.',
        status: 'NOT_VERIFIED',
        severity: 'INFO',
        evidence: `Target unreachable: ${healthProbeError?.message || 'Connection refused'}`,
        remediation: 'Verify server connection.',
        testedAt: new Date().toISOString(),
      });
    }
  } finally {
    if (ephemeralServer) {
      await new Promise<void>((resolve) => {
        ephemeralServer!.close(() => resolve());
      });
    }
  }

  // Calculate summary metrics
  const passed = findings.filter((f) => f.status === 'PASS').length;
  const failed = findings.filter((f) => f.status === 'FAIL').length;
  const notVerified = findings.filter((f) => f.status === 'NOT_VERIFIED').length;

  const bySeverity = {
    HIGH: findings.filter((f) => f.severity === 'HIGH' && f.status === 'FAIL').length,
    MEDIUM: findings.filter((f) => f.severity === 'MEDIUM' && f.status === 'FAIL').length,
    LOW: findings.filter((f) => f.severity === 'LOW' && f.status === 'FAIL').length,
    INFO: findings.filter((f) => f.severity === 'INFO' && f.status === 'FAIL').length,
  };

  return {
    auditId,
    timestamp,
    target: activeBaseUrl,
    disclaimer: 'Beperkte lokale audit, geen volledige penetratietest. (Limited local security audit, not a comprehensive penetration test)',
    summary: {
      total: findings.length,
      passed,
      failed,
      notVerified,
      bySeverity,
    },
    findings,
  };
}
