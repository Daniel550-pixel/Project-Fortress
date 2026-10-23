/**
 * Project Fortress — Cryptographic Authentication & RBAC Engine
 * @license Apache-2.0
 */

import { SecurityRole, SecurityPermission, SecurityTokenPayload, SecurityUser } from './types.ts';
import { AuthenticationError, AuthorizationError } from './errors.ts';

// Role-to-Permissions Mapping (Least Privilege Enforcement)
export const ROLE_PERMISSIONS: Record<SecurityRole, SecurityPermission[]> = {
  ADMIN: [
    'read:telemetry',
    'write:policy',
    'execute:remediation',
    'read:audit',
    'rotate:keys',
    'simulate:attack',
    'read:system',
  ],
  SECOPS: [
    'read:telemetry',
    'write:policy',
    'execute:remediation',
    'read:audit',
    'simulate:attack',
    'read:system',
  ],
  AUDIT: ['read:telemetry', 'read:audit', 'read:system'],
  SERVICE: ['read:telemetry', 'read:system'],
  ANONYMOUS: [],
};

// Base64URL encoding/decoding utilities
function toBase64Url(str: string): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(str, 'utf8').toString('base64url');
  }
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(b64url: string): string {
  let base64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(base64, 'base64').toString('utf8');
  }
  return atob(base64);
}

/**
 * Generates an HMAC-SHA256 signature string for token data.
 */
export async function createHmacSignature(data: string, secret: string): Promise<string> {
  // Use WebCrypto if available (modern Node.js and modern browsers)
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    const enc = new TextEncoder();
    const key = await globalThis.crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sigBuf = await globalThis.crypto.subtle.sign('HMAC', key, enc.encode(data));
    const bytes = new Uint8Array(sigBuf);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return toBase64Url(binary);
  }

  // Fallback to node:crypto
  const nodeCrypto = await import('node:crypto');
  return nodeCrypto.createHmac('sha256', secret).update(data).digest('base64url');
}

/**
 * Constant-time comparison to prevent timing attacks.
 */
export function timingSafeEqualString(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

/**
 * Issues a cryptographically signed Fortress Bearer Token.
 */
export async function issueToken(
  user: Omit<SecurityUser, 'permissions'>,
  secret: string,
  ttlSeconds = 3600,
  issuer = 'fortress-auth-gateway',
  audience = 'fortress-services'
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const permissions = ROLE_PERMISSIONS[user.role] || [];

  const header = {
    alg: 'HS256',
    typ: 'FORTRESS-TOKEN',
  };

  const payload: SecurityTokenPayload = {
    sub: user.id,
    username: user.username,
    role: user.role,
    permissions,
    tenantId: user.tenantId,
    iat: now,
    exp: now + ttlSeconds,
    iss: issuer,
    aud: audience,
    jti: `tok_${Math.random().toString(36).substring(2, 12)}`,
  };

  const headerEncoded = toBase64Url(JSON.stringify(header));
  const payloadEncoded = toBase64Url(JSON.stringify(payload));
  const dataToSign = `${headerEncoded}.${payloadEncoded}`;

  const signature = await createHmacSignature(dataToSign, secret);
  return `${dataToSign}.${signature}`;
}

/**
 * Verifies a Fortress Bearer Token; rejects expired, tampered, or malformed tokens.
 */
export async function verifyToken(
  token: string,
  secret: string,
  expectedIssuer = 'fortress-auth-gateway',
  expectedAudience = 'fortress-services'
): Promise<SecurityTokenPayload> {
  if (!token || typeof token !== 'string') {
    throw new AuthenticationError('Token missing or not a string');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new AuthenticationError('Malformed token format (expected 3 parts)');
  }

  const [headerEncoded, payloadEncoded, signature] = parts;
  const dataToSign = `${headerEncoded}.${payloadEncoded}`;

  const expectedSignature = await createHmacSignature(dataToSign, secret);
  if (!timingSafeEqualString(signature, expectedSignature)) {
    throw new AuthenticationError('Cryptographic signature verification failed (tampered or forged token)');
  }

  let payload: SecurityTokenPayload;
  try {
    payload = JSON.parse(fromBase64Url(payloadEncoded));
  } catch {
    throw new AuthenticationError('Unreadable token payload');
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now) {
    throw new AuthenticationError(`Token expired at ${new Date(payload.exp * 1000).toISOString()}`);
  }

  if (payload.iss !== expectedIssuer) {
    throw new AuthenticationError(`Token issuer mismatch: expected '${expectedIssuer}', got '${payload.iss}'`);
  }

  if (payload.aud !== expectedAudience) {
    throw new AuthenticationError(`Token audience mismatch: expected '${expectedAudience}', got '${payload.aud}'`);
  }

  return payload;
}

/**
 * Enforces role-based or permission-based authorization boundary.
 */
export function authorizeCapability(
  tokenPayload: SecurityTokenPayload,
  requiredPermission: SecurityPermission
): void {
  const allowed = tokenPayload.permissions.includes(requiredPermission);
  if (!allowed) {
    throw new AuthorizationError(
      `Role '${tokenPayload.role}' lacks required capability '${requiredPermission}'`
    );
  }
}
