/**
 * Project Fortress — Production-Grade Security Gateway & Application Server
 * @license Apache-2.0
 */

import express, { Request, Response, NextFunction } from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateAndLoadConfig, maskConfig } from './src/security/config.ts';
import { inspectInput, validateOutgoingUrl } from './src/security/sanitizer.ts';
import { issueToken, verifyToken, authorizeCapability } from './src/security/auth.ts';
import { TokenBucketRateLimiter } from './src/security/rateLimiter.ts';
import { securityLogger } from './src/security/logger.ts';
import { runSecurityVerificationPipeline } from './src/security/pipeline.ts';
import { runSecurityAudit } from './src/security/audit.ts';
import { FortressError, SecurityThreatDetectedError } from './src/security/errors.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const isDev = process.env.NODE_ENV !== 'production';

const config = validateAndLoadConfig(process.env);
const app = express();
const rateLimiter = new TokenBucketRateLimiter(config.rateLimitMaxRequests, config.rateLimitWindowMs);
const serverStartTime = Date.now();

// 1. Strict Security Headers Middleware
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' ws: http: https:;"
  );
  next();
});

// 2. Disallowed HTTP Methods Guard (blocks TRACE, TRACK with 405 Method Not Allowed)
const DISALLOWED_METHODS = new Set(['TRACE', 'TRACK']);
app.use((req: Request, res: Response, next: NextFunction) => {
  if (DISALLOWED_METHODS.has(req.method.toUpperCase())) {
    res.setHeader('Allow', 'GET, POST, HEAD, OPTIONS');
    securityLogger.log('DISALLOWED_METHOD_BLOCKED', 'MEDIUM', 'anonymous', req.ip || 'unknown', {
      method: req.method,
      path: req.path,
    });
    return res.status(405).json({
      error: {
        code: 'METHOD_NOT_ALLOWED',
        message: `HTTP method ${req.method} is disallowed by security policy.`,
      },
    });
  }
  next();
});

// 3. Internal Source Code, Secrets & VCS File Protection Middleware
const FORBIDDEN_EXTENSIONS = new Set([
  '.env', '.ts', '.tsx', '.mjs', '.cjs', '.map', '.sh', '.yml', '.yaml', '.bak', '.git', '.sql', '.conf'
]);
const FORBIDDEN_EXACT_FILES = new Set([
  '/.env',
  '/.env.example',
  '/package.json',
  '/tsconfig.json',
  '/server.ts',
  '/server.ts.bak',
]);

app.use((req: Request, res: Response, next: NextFunction) => {
  const pathname = req.path.toLowerCase();
  const ext = path.extname(pathname);

  const isVcsPath = pathname.startsWith('/.git');
  const isEnvPath = pathname.startsWith('/.env');
  const isInternalSensitiveFile = FORBIDDEN_EXACT_FILES.has(pathname);
  const isSecretExtension = ['.env', '.sql', '.map', '.sh', '.yml', '.yaml', '.bak'].includes(ext);

  const isSourceProbe =
    pathname === '/server.ts' ||
    pathname.startsWith('/src/security/') ||
    pathname === '/src/app.tsx' ||
    pathname.startsWith('/tests/') ||
    pathname.startsWith('/deploy/') ||
    pathname.startsWith('/scripts/') ||
    (!isDev && (pathname.startsWith('/src/') || ext === '.ts' || ext === '.tsx'));

  if (isVcsPath || isEnvPath || isInternalSensitiveFile || isSecretExtension || isSourceProbe) {
    securityLogger.log('UNAUTHORIZED_FILE_ACCESS', 'HIGH', 'anonymous', req.ip || 'unknown', {
      path: req.path,
    });
    return res.status(403).json({
      error: {
        code: 'FORBIDDEN_FILE_ACCESS',
        message: 'Direct access to internal source files, credentials, and manifests is prohibited.',
      },
    });
  }
  next();
});

// 2. Global Rate Limiter Middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const status = rateLimiter.consume(clientIp);

  res.setHeader('X-RateLimit-Limit', status.limit.toString());
  res.setHeader('X-RateLimit-Remaining', status.remaining.toString());

  if (!status.allowed) {
    res.setHeader('Retry-After', (status.retryAfterSec || 1).toString());
    securityLogger.log('RATE_LIMITED', 'MEDIUM', 'anonymous', clientIp, {
      path: req.path,
      retryAfter: status.retryAfterSec,
    });
    return res.status(429).json({
      error: {
        code: 'TOO_MANY_REQUESTS',
        message: 'Rate limit exceeded. Please back off.',
        retryAfterSec: status.retryAfterSec,
      },
    });
  }
  next();
});

// 3. Bounded JSON & URL-encoded Parsers
app.use(express.json({ limit: config.maxBodySizeBytes }));
app.use(express.urlencoded({ extended: false, limit: config.maxBodySizeBytes }));

// --- API ENDPOINTS ---

/**
 * Health Check Endpoint
 * Strictly returns operational status without disclosing host paths, software versions, or keys.
 */
app.get('/api/health', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'HEALTHY',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor((Date.now() - serverStartTime) / 1000),
  });
});

/**
 * Automated Verification Pipeline Execution Endpoint
 */
app.get('/api/verify', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const report = await runSecurityVerificationPipeline();
    res.status(200).json(report);
  } catch (err) {
    next(err);
  }
});

/**
 * Live Input Sanitization & Attack Detection Endpoint
 */
app.post('/api/sanitize', (req: Request, res: Response) => {
  const { input, url } = req.body;
  const result: Record<string, unknown> = {};

  if (typeof input === 'string') {
    result.inputInspection = inspectInput(input);
  }

  if (typeof url === 'string') {
    result.urlValidation = validateOutgoingUrl(url);
  }

  res.status(200).json(result);
});

/**
 * Cryptographic Token Issuance Endpoint
 */
app.post('/api/auth/token', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { username, role } = req.body;
    if (!username || !role) {
      return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Missing username or role' } });
    }

    const token = await issueToken(
      {
        id: `usr-${Date.now().toString(36)}`,
        username: String(username),
        role: role,
        tenantId: 'tenant-default',
      },
      config.hmacSecret,
      config.tokenTtlSeconds
    );

    const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    securityLogger.log('AUTH_SUCCESS', 'LOW', String(username), clientIp, { action: 'TOKEN_ISSUED', role });

    res.status(200).json({ token });
  } catch (err) {
    next(err);
  }
});

/**
 * Cryptographic Token Verification Endpoint
 */
app.post('/api/auth/verify', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token } = req.body;
    if (!token || typeof token !== 'string') {
      return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Missing token string' } });
    }

    const payload = await verifyToken(token, config.hmacSecret);
    res.status(200).json({ valid: true, payload });
  } catch (err) {
    if (err instanceof FortressError) {
      return res.status(err.statusCode).json(err.toClientSafeResponse());
    }
    next(err);
  }
});

/**
 * Audit Telemetry Stream Endpoint
 */
app.get('/api/audit', (_req: Request, res: Response) => {
  const events = securityLogger.getRecentEvents(50);
  res.status(200).json({ events });
});

/**
 * Automated Security Audit Endpoint
 * Performs modular runtime inspection of headers, static allowlist, HTTP methods, route handling, and source exposure.
 */
app.get('/api/security/audit', async (req: Request, res: Response, next: NextFunction) => {
  try {
    let targetUrl: string | undefined;
    if (typeof req.query.target === 'string') {
      try {
        const parsed = new URL(req.query.target);
        if (parsed.hostname !== '127.0.0.1' && parsed.hostname !== 'localhost') {
          return res.status(400).json({
            error: {
              code: 'INVALID_AUDIT_TARGET',
              message: 'Audit target must be a local loopback address (127.0.0.1).',
            },
          });
        }
        targetUrl = req.query.target;
      } catch {
        return res.status(400).json({
          error: {
            code: 'INVALID_AUDIT_TARGET',
            message: 'Malformed target URL provided.',
          },
        });
      }
    }

    const report = await runSecurityAudit(app, { targetUrl });
    const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    securityLogger.log('SECURITY_AUDIT_RUN', 'LOW', 'audit-service', clientIp, {
      auditId: report.auditId,
      totalChecks: report.summary.total,
      passed: report.summary.passed,
      failed: report.summary.failed,
      notVerified: report.summary.notVerified,
    });

    res.status(200).json(report);
  } catch (err) {
    next(err);
  }
});

/**
 * Fallback handler for all undefined /api/* routes
 * Returns clean 404 JSON response preventing SPA HTML leaks or unhandled exceptions.
 */
app.all('/api/*', (req: Request, res: Response) => {
  res.status(404).json({
    error: {
      code: 'NOT_FOUND',
      message: `The requested API endpoint ${req.path} was not found.`,
    },
  });
});

/**
 * Centralized Safe Error Handling Middleware
 * Guaranteed to intercept all route, syntax, and parsing errors, returning structured JSON without stack traces.
 */
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof FortressError) {
    return res.status(err.statusCode).json(err.toClientSafeResponse());
  }

  // Handle JSON parse errors from body-parser safely without leaking internal paths
  if (err instanceof SyntaxError && 'status' in err && (err as any).status === 400) {
    return res.status(400).json({
      error: {
        code: 'BAD_REQUEST',
        message: 'Malformed JSON payload syntax.',
      },
    });
  }

  // Never leak stack traces or raw internal errors to clients
  res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An internal security policy halted this request.',
      timestamp: new Date().toISOString(),
    },
  });
});

// --- CLIENT SERVING ---
async function startServer() {
  const isDev = process.env.NODE_ENV !== 'production';

  if (isDev) {
    // Development Mode: Mount Vite in middleware mode
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    // Production Mode: Serve static files from dist
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  return app.listen(config.port, '0.0.0.0', () => {
    console.log(`[PROJECT FORTRESS] Security Gateway running on port ${config.port} (env: ${config.nodeEnv})`);
  });
}

const isTestEnvironment = process.env.NODE_ENV === 'test' || process.argv.some((arg) => arg.includes('test'));

if (!isTestEnvironment) {
  startServer().catch((err) => {
    console.error('[FATAL] Fortress Gateway failed to initialize:', err);
    process.exit(1);
  });
}

export { app, config, startServer };
