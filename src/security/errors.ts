/**
 * Project Fortress — Secure Error Taxonomy & Sanitization
 * @license Apache-2.0
 */

export class FortressError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly isOperational: boolean;
  public readonly timestamp: string;

  constructor(message: string, code = 'FORTRESS_ERROR', statusCode = 500, isOperational = true) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.timestamp = new Date().toISOString();
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * Serializes error for public client consumption.
   * Strips stack traces, internal paths, and sensitive tokens.
   */
  public toClientSafeResponse(): { error: { code: string; message: string; timestamp: string } } {
    return {
      error: {
        code: this.code,
        message: this.isOperational ? this.message : 'An internal security policy halted this request.',
        timestamp: this.timestamp,
      },
    };
  }
}

export class ValidationError extends FortressError {
  constructor(message: string, details?: unknown) {
    super(message, 'VALIDATION_FAILED', 400);
  }
}

export class AuthenticationError extends FortressError {
  constructor(message = 'Authentication failed or token invalid') {
    super(message, 'UNAUTHORIZED', 401);
  }
}

export class AuthorizationError extends FortressError {
  constructor(message = 'Access denied: insufficient capabilities') {
    super(message, 'FORBIDDEN', 403);
  }
}

export class RateLimitExceededError extends FortressError {
  public readonly retryAfterSec: number;

  constructor(retryAfterSec: number, message = 'Rate limit exceeded. Please back off.') {
    super(message, 'TOO_MANY_REQUESTS', 429);
    this.retryAfterSec = retryAfterSec;
  }
}

export class SecurityThreatDetectedError extends FortressError {
  public readonly threatType: string;

  constructor(threatType: string, message = 'Malicious payload detected by Fortress Gateway') {
    super(message, 'THREAT_BLOCKED', 400);
    this.threatType = threatType;
  }
}

/**
 * Sanitizes any raw exception or object before logging or responding,
 * scrubbing file paths, passwords, and tokens.
 */
export function sanitizeError(err: unknown): { code: string; message: string; sanitized: boolean } {
  if (err instanceof FortressError) {
    return {
      code: err.code,
      message: err.message,
      sanitized: true,
    };
  }

  const rawMsg = err instanceof Error ? err.message : String(err);
  // Redact potential memory addresses, absolute paths, or credentials in error messages
  const sanitizedMsg = rawMsg
    .replace(/(?:file:\/\/\/|\/[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_.-]+)+)/g, '[INTERNAL_PATH]')
    .replace(/(?:bearer|token|key|secret|password)[=:\s]+[^\s,;&]+/gi, '[REDACTED_CREDENTIAL]');

  return {
    code: 'INTERNAL_ERROR',
    message: 'An unexpected runtime error occurred.',
    sanitized: true,
  };
}
