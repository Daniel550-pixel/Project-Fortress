/**
 * Project Fortress — Structured Sanitized Security Logging
 * @license Apache-2.0
 */

import { AuditEvent, ThreatLevel } from './types.ts';

// Deterministic redaction patterns
const REDACTION_PATTERNS = [
  // JWTs and Bearer tokens
  { regex: /eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]+/g, replacement: '[REDACTED_JWT]' },
  { regex: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, replacement: 'Bearer [REDACTED_TOKEN]' },
  // AWS Access Key ID
  { regex: /\bAKIA[0-9A-Z]{16}\b/g, replacement: '[REDACTED_AWS_KEY]' },
  // Passwords and API keys in key-value pairs or JSON
  { regex: /(["']?(?:password|secret|apiKey|api_key|token|auth_token|privateKey|private_key)["']?\s*[:=]\s*["'])([^"']{3,})(["'])/gi, replacement: '$1[REDACTED_SECRET]$3' },
  // Private keys (PEM format)
  { regex: /-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----[\s\S]*?-----END\s+[A-Z\s]+PRIVATE\s+KEY-----/gi, replacement: '[REDACTED_PRIVATE_KEY]' },
  // Credit card numbers (basic 13-19 digits)
  { regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, replacement: '[REDACTED_PAN]' },
];

/**
 * Deeply redacts sensitive strings and object properties.
 */
export function redactSensitiveData<T>(input: T): T {
  if (input === null || input === undefined) {
    return input;
  }

  if (typeof input === 'string') {
    let result: string = input;
    for (const { regex, replacement } of REDACTION_PATTERNS) {
      result = result.replace(regex, replacement);
    }
    return result as unknown as T;
  }

  if (Array.isArray(input)) {
    return input.map((item) => redactSensitiveData(item)) as unknown as T;
  }

  if (typeof input === 'object') {
    const copy: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input)) {
      const lowerKey = key.toLowerCase();
      if (
        lowerKey.includes('password') ||
        lowerKey.includes('secret') ||
        lowerKey.includes('apikey') ||
        lowerKey.includes('api_key') ||
        lowerKey.includes('token') ||
        lowerKey.includes('privatekey') ||
        lowerKey.includes('authorization')
      ) {
        copy[key] = '[REDACTED]';
      } else {
        copy[key] = redactSensitiveData(value);
      }
    }
    return copy as unknown as T;
  }

  return input;
}

class SecurityLogger {
  private auditRingBuffer: AuditEvent[] = [];
  private readonly maxBufferSize = 200;

  /**
   * Logs a structured, sanitized security event.
   */
  public log(
    eventType: AuditEvent['eventType'],
    severity: ThreatLevel,
    principal: string,
    sourceIp: string,
    details: Record<string, unknown>
  ): AuditEvent {
    const sanitizedDetails = redactSensitiveData(details) as Record<string, unknown>;

    const event: AuditEvent = {
      id: `sec-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
      timestamp: new Date().toISOString(),
      eventType,
      severity,
      sourceIp: redactSensitiveData(sourceIp) as string,
      principal: redactSensitiveData(principal) as string,
      details: sanitizedDetails,
      redacted: true,
    };

    // Store in ring buffer
    this.auditRingBuffer.unshift(event);
    if (this.auditRingBuffer.length > this.maxBufferSize) {
      this.auditRingBuffer.pop();
    }

    return event;
  }

  public getRecentEvents(limit = 50): AuditEvent[] {
    return [...this.auditRingBuffer.slice(0, limit)];
  }

  public clear(): void {
    this.auditRingBuffer = [];
  }
}

export const securityLogger = new SecurityLogger();
