import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  return {
    plugins: [
      react(),
      tailwindcss(),
      {
        name: 'api-audit-dev-handler',
        configureServer(server) {
          server.middlewares.use(async (req, res, next) => {
            const urlPath = (req.url?.split('?')[0] || '').toLowerCase();
            const ext = path.extname(urlPath);

            // 1. Strict Security Headers
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.setHeader('X-Frame-Options', 'SAMEORIGIN');
            res.setHeader('X-XSS-Protection', '1; mode=block');
            res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
            res.setHeader('Content-Security-Policy', "default-src 'self' 'unsafe-inline' data:; connect-src 'self' ws: http: https:;");
            res.setHeader('X-RateLimit-Limit', '100');
            res.setHeader('X-RateLimit-Remaining', '99');

            // 2. Disallowed HTTP Methods Guard
            if (req.method === 'TRACE' || req.method === 'TRACK') {
              res.statusCode = 405;
              res.setHeader('Allow', 'GET, POST, HEAD, OPTIONS');
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify({ error: { code: 'METHOD_NOT_ALLOWED', message: `Method ${req.method} disallowed.` } }));
              return;
            }

            // 3. Sensitive File & Source Code Shielding
            if (
              urlPath === '/.env' ||
              urlPath.startsWith('/.git') ||
              urlPath === '/server.ts' ||
              urlPath === '/package.json' ||
              urlPath === '/tsconfig.json' ||
              urlPath.startsWith('/src/security/') ||
              ['.env', '.sql', '.map', '.yml', '.yaml', '.sh'].includes(ext)
            ) {
              res.statusCode = 403;
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify({ error: { code: 'FORBIDDEN_FILE_ACCESS', message: 'Direct access to internal source files and protected manifests is prohibited.' } }));
              return;
            }

            // 4. API Endpoints
            if (urlPath === '/api/security/audit') {
              try {
                const { runSecurityAudit } = await import('./src/security/audit.ts');
                const urlObj = new URL(req.url!, 'http://127.0.0.1:3000');
                const target = urlObj.searchParams.get('target') || 'http://127.0.0.1:3000';
                const report = await runSecurityAudit(undefined, {
                  targetUrl: target,
                });
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify(report));
                return;
              } catch (err: any) {
                res.statusCode = 500;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({ error: { message: err.message } }));
                return;
              }
            }

            if (urlPath === '/api/health') {
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify({ status: 'HEALTHY', timestamp: new Date().toISOString() }));
              return;
            }

            // 5. Unknown API routes fallback
            if (urlPath.startsWith('/api/')) {
              res.statusCode = 404;
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: `The requested API endpoint ${urlPath} was not found.` } }));
              return;
            }

            next();
          });
        },
      },
    ],
    resolve: {
      alias: {
        '@': path.resolve('.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
