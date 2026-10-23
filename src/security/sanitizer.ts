/**
 * Project Fortress — Input Validation, SSRF Guard, and Attack Detection
 * @license Apache-2.0
 */

import { SanitizationResult } from './types.ts';
import { SecurityThreatDetectedError, ValidationError } from './errors.ts';

// Comprehensive attack detection patterns
const ATTACK_VECTORS = [
  {
    type: 'SQLI' as const,
    regex: /(\b(SELECT|UNION|INSERT|DELETE|DROP|ALTER|UPDATE|TRUNCATE)\b[\s\S]*?\b(FROM|INTO|TABLE|WHERE|SET)\b)|(--\s*$)|(\bOR\s+['"]?1['"]?\s*=\s*['"]?1)|(\bAND\s+['"]?1['"]?\s*=\s*['"]?1)|(\bBENCHMARK\s*\()|(\bSLEEP\s*\()/i,
    description: 'SQL Injection signature detected (query clause or boolean condition)',
  },
  {
    type: 'NOSQLI' as const,
    regex: /(\$where|\$regex|\$gt|\$gte|\$ne|\$nin|\$exists|\$lookup|\$mod)\s*:/i,
    description: 'NoSQL operator injection detected',
  },
  {
    type: 'CMD_INJECTION' as const,
    regex: /(;\s*(?:rm|cat|ls|curl|wget|bash|sh|nc|ncat|python|perl|powershell)\b)|(\|\s*(?:bash|sh|python))|(`[^`]+`)|(\$\([^)]+\))|(&&\s*(?:cat|rm|bash))/i,
    description: 'OS Command injection syntax detected',
  },
  {
    type: 'PATH_TRAVERSAL' as const,
    regex: /(\.\.[/\\])|(\.\.%2f)|(%2e%2e[/\\])|(\/etc\/(?:passwd|shadow|hosts))|(C:[\\/]Windows[\\/])/i,
    description: 'Directory path traversal attempt detected',
  },
  {
    type: 'XSS' as const,
    regex: /(<script[\s\S]*?>[\s\S]*?<\/script>)|(javascript:\s*[^\s]+)|(onerror\s*=\s*['"]?[^'"]+['"]?)|(<img[\s\S]*?onerror=)|(<iframe[\s\S]*?>)/i,
    description: 'Cross-Site Scripting (XSS) payload detected',
  },
];

/**
 * Inspects any string input for known injection patterns.
 */
export function inspectInput(input: string): SanitizationResult {
  const detectedThreats: SanitizationResult['detectedThreats'] = [];

  for (const vector of ATTACK_VECTORS) {
    if (vector.regex.test(input)) {
      detectedThreats.push({
        type: vector.type,
        confidence: 'DEFINITE',
        matchedPattern: vector.regex.source.slice(0, 40),
        description: vector.description,
      });
    }
  }

  // Null-byte injection check
  if (input.includes('\0') || input.includes('%00')) {
    detectedThreats.push({
      type: 'PATH_TRAVERSAL',
      confidence: 'DEFINITE',
      matchedPattern: 'NULL_BYTE',
      description: 'Poison null byte detected in input string',
    });
  }

  return {
    isClean: detectedThreats.length === 0,
    sanitizedValue: escapeHtml(input),
    detectedThreats,
  };
}

/**
 * Validates and enforces clean input; throws SecurityThreatDetectedError if attacks found.
 */
export function assertSafeInput(input: string, fieldName = 'input'): string {
  const result = inspectInput(input);
  if (!result.isClean) {
    const primary = result.detectedThreats[0];
    throw new SecurityThreatDetectedError(primary.type, `Field '${fieldName}' blocked: ${primary.description}`);
  }
  return input;
}

/**
 * Context-aware HTML entity encoding.
 */
export function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * SSRF Guard: Validates that an outgoing target URL is safe and not targeting
 * loopback, internal RFC-1918 addresses, or cloud metadata endpoints.
 */
export function validateOutgoingUrl(rawUrl: string): { isValid: boolean; parsedUrl: URL; reason?: string } {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { isValid: false, parsedUrl: {} as URL, reason: 'Malformed URL format' };
  }

  // Only HTTP/HTTPS allowed
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { isValid: false, parsedUrl: parsed, reason: `Disallowed protocol: '${parsed.protocol}'. Only http: and https: permitted.` };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Block localhost and loopback names
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '0.0.0.0' || hostname === '::1' || hostname === '[::1]') {
    return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: Loopback / localhost access prohibited' };
  }

  // Block AWS / GCP / Azure Instance Metadata Service (169.254.169.254)
  if (hostname === '169.254.169.254' || hostname.startsWith('169.254.')) {
    return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: Cloud Instance Metadata Service (169.254.x.x) prohibited' };
  }

  // Check IPv4 private address ranges
  const ipv4Match = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [, o1, o2] = ipv4Match.map(Number);
    // 10.0.0.0/8
    if (o1 === 10) {
      return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: Private RFC-1918 range (10.0.0.0/8) prohibited' };
    }
    // 172.16.0.0/12
    if (o1 === 172 && o2 >= 16 && o2 <= 31) {
      return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: Private RFC-1918 range (172.16.0.0/12) prohibited' };
    }
    // 192.168.0.0/16
    if (o1 === 192 && o2 === 168) {
      return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: Private RFC-1918 range (192.168.0.0/16) prohibited' };
    }
    // 127.0.0.0/8
    if (o1 === 127) {
      return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: Loopback range (127.0.0.0/8) prohibited' };
    }
    // 0.0.0.0/8
    if (o1 === 0) {
      return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: Non-routable range (0.0.0.0/8) prohibited' };
    }
  }

  // Block dangerous internal ports
  const port = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === 'https:' ? 443 : 80;
  const dangerousPorts = [22, 23, 25, 3306, 5432, 6379, 27017, 9200, 2375, 2379];
  if (dangerousPorts.includes(port)) {
    return { isValid: false, parsedUrl: parsed, reason: `SSRF Block: High-risk internal service port (${port}) prohibited` };
  }

  return { isValid: true, parsedUrl: parsed };
}
