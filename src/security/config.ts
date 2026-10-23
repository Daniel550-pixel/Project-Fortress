/**
 * Project Fortress — Strict Configuration Validation Subsystem
 * @license Apache-2.0
 */

import { ValidationError } from './errors.ts';

export interface FortressConfig {
  nodeEnv: 'production' | 'staging' | 'development' | 'test';
  port: number;
  hmacSecret: string;
  tokenTtlSeconds: number;
  rateLimitWindowMs: number;
  rateLimitMaxRequests: number;
  allowedOrigins: string[];
  enforceStrictIsolation: boolean;
  maxBodySizeBytes: number;
}

export function validateAndLoadConfig(rawEnv: Record<string, string | undefined>): FortressConfig {
  const nodeEnv = (rawEnv.NODE_ENV || 'production').toLowerCase();
  if (!['production', 'staging', 'development', 'test'].includes(nodeEnv)) {
    throw new ValidationError(`Invalid NODE_ENV: '${rawEnv.NODE_ENV}'. Must be production, staging, development, or test.`);
  }

  const port = parseInt(rawEnv.PORT || '3000', 10);
  if (isNaN(port) || port < 1024 || port > 65535) {
    throw new ValidationError(`Invalid PORT: '${rawEnv.PORT}'. Must be an unprivileged port between 1024 and 65535.`);
  }

  const hmacSecret = rawEnv.FORTRESS_HMAC_SECRET || rawEnv.HMAC_SECRET || 'fortress-secure-default-key-32-chars-long-min!';
  if (hmacSecret.length < 32) {
    throw new ValidationError('FORTRESS_HMAC_SECRET must be at least 32 characters long for cryptographic security.');
  }

  // Reject common default/trivial keys
  const weakKeys = ['password', '12345678901234567890123456789012', 'secretsecretsecretsecretsecret32', 'adminadminadminadminadminadmin32'];
  if (weakKeys.includes(hmacSecret.toLowerCase())) {
    throw new ValidationError('Insecure HMAC secret rejected: commonly known weak or repetitive pattern.');
  }

  const tokenTtlSeconds = parseInt(rawEnv.TOKEN_TTL_SECONDS || '3600', 10);
  if (isNaN(tokenTtlSeconds) || tokenTtlSeconds < 60 || tokenTtlSeconds > 86400) {
    throw new ValidationError(`Invalid TOKEN_TTL_SECONDS: must be between 60s and 86400s (24h). Got ${tokenTtlSeconds}`);
  }

  const rateLimitWindowMs = parseInt(rawEnv.RATE_LIMIT_WINDOW_MS || '60000', 10);
  if (isNaN(rateLimitWindowMs) || rateLimitWindowMs < 1000) {
    throw new ValidationError('Invalid RATE_LIMIT_WINDOW_MS: must be at least 1000ms.');
  }

  const rateLimitMaxRequests = parseInt(rawEnv.RATE_LIMIT_MAX_REQUESTS || '100', 10);
  if (isNaN(rateLimitMaxRequests) || rateLimitMaxRequests <= 0) {
    throw new ValidationError('Invalid RATE_LIMIT_MAX_REQUESTS: must be a positive integer.');
  }

  const rawOrigins = rawEnv.ALLOWED_ORIGINS || 'https://localhost:3000,http://localhost:3000';
  const allowedOrigins = rawOrigins.split(',').map((o) => o.trim()).filter(Boolean);

  // Reject dangerous wildcard in production
  if (nodeEnv === 'production' && allowedOrigins.includes('*')) {
    throw new ValidationError('Wildcard CORS origin (*) is forbidden in production environment.');
  }

  const maxBodySizeBytes = parseInt(rawEnv.MAX_BODY_SIZE_BYTES || '1048576', 10); // 1MB default
  if (isNaN(maxBodySizeBytes) || maxBodySizeBytes <= 0 || maxBodySizeBytes > 10485760) {
    throw new ValidationError('Invalid MAX_BODY_SIZE_BYTES: must be between 1 byte and 10MB.');
  }

  return {
    nodeEnv: nodeEnv as FortressConfig['nodeEnv'],
    port,
    hmacSecret,
    tokenTtlSeconds,
    rateLimitWindowMs,
    rateLimitMaxRequests,
    allowedOrigins,
    enforceStrictIsolation: rawEnv.ENFORCE_STRICT_ISOLATION !== 'false',
    maxBodySizeBytes,
  };
}

export function maskConfig(config: FortressConfig): Record<string, unknown> {
  return {
    ...config,
    hmacSecret: `***REDACTED (length: ${config.hmacSecret.length})***`,
  };
}
