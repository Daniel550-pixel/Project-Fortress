/**
 * Project Fortress — Input Validation, SSRF Guard, and Attack Detection
 * @license Apache-2.0
 */

import { SanitizationResult } from './types.ts';
import { SecurityThreatDetectedError } from './errors.ts';

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
 * Parses any numeric IPv4 address format (decimal, octal, hex, dword)
 * into a standard 32-bit unsigned integer, or returns null if not an IP.
 */
export function parseIpv4ToNumber(rawHost: string): number | null {
  const host = rawHost.trim().toLowerCase();

  // 1. Single integer / dword format: e.g. "2130706433" or "0x7f000001"
  if (/^(?:0x[0-9a-f]+|\d+)$/.test(host)) {
    const num = host.startsWith('0x') ? parseInt(host, 16) : parseInt(host, 10);
    if (!isNaN(num) && num >= 0 && num <= 0xffffffff) {
      return num >>> 0;
    }
  }

  // 2. Dotted parts (1 to 4 parts)
  const parts = host.split('.');
  if (parts.length < 1 || parts.length > 4) {
    return null;
  }

  const nums: number[] = [];
  for (const part of parts) {
    if (!part || !/^(?:0x[0-9a-f]+|0[0-7]+|\d+)$/i.test(part)) {
      return null;
    }
    let val: number;
    if (part.startsWith('0x') || part.startsWith('0X')) {
      val = parseInt(part, 16);
    } else if (part.length > 1 && part.startsWith('0')) {
      val = parseInt(part, 8); // Octal IP representation
    } else {
      val = parseInt(part, 10);
    }
    if (isNaN(val) || val < 0) {
      return null;
    }
    nums.push(val);
  }

  // Check limits per part according to standard inet_aton rules
  if (parts.length === 4) {
    if (nums.some((n) => n > 255)) return null;
    return (((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0);
  } else if (parts.length === 3) {
    if (nums[0] > 255 || nums[1] > 255 || nums[2] > 0xffff) return null;
    return (((nums[0] << 24) | (nums[1] << 16) | nums[2]) >>> 0);
  } else if (parts.length === 2) {
    if (nums[0] > 255 || nums[1] > 0xffffff) return null;
    return (((nums[0] << 24) | nums[1]) >>> 0);
  } else if (parts.length === 1) {
    if (nums[0] > 0xffffffff) return null;
    return nums[0] >>> 0;
  }

  return null;
}

/**
 * Checks whether a 32-bit unsigned IPv4 number falls within non-routable, private, or loopback ranges.
 */
export function isPrivateOrReservedIpv4(ipNum: number): { isBlocked: boolean; reason?: string } {
  const o1 = (ipNum >>> 24) & 0xff;
  const o2 = (ipNum >>> 16) & 0xff;

  // 0.0.0.0/8 (Current network)
  if (o1 === 0) return { isBlocked: true, reason: 'SSRF Block: Non-routable network (0.0.0.0/8)' };

  // 10.0.0.0/8 (RFC-1918 Private)
  if (o1 === 10) return { isBlocked: true, reason: 'SSRF Block: Private RFC-1918 range (10.0.0.0/8)' };

  // 100.64.0.0/10 (Carrier-Grade NAT RFC-6598)
  if (o1 === 100 && o2 >= 64 && o2 <= 127) {
    return { isBlocked: true, reason: 'SSRF Block: Shared Carrier-Grade NAT range (100.64.0.0/10)' };
  }

  // 127.0.0.0/8 (Loopback)
  if (o1 === 127) return { isBlocked: true, reason: 'SSRF Block: Loopback range (127.0.0.0/8)' };

  // 169.254.0.0/16 (Link-Local / Cloud Instance Metadata Service)
  if (o1 === 169 && o2 === 254) {
    return { isBlocked: true, reason: 'SSRF Block: Cloud Instance Metadata Service / Link-Local (169.254.0.0/16)' };
  }

  // 172.16.0.0/12 (RFC-1918 Private)
  if (o1 === 172 && o2 >= 16 && o2 <= 31) {
    return { isBlocked: true, reason: 'SSRF Block: Private RFC-1918 range (172.16.0.0/12)' };
  }

  // 192.0.0.0/24 (IETF Protocol Assignments)
  if (o1 === 192 && o2 === 0) {
    const o3 = (ipNum >>> 8) & 0xff;
    if (o3 === 0 || o3 === 2) return { isBlocked: true, reason: 'SSRF Block: IETF Protocol / TEST-NET-1 (192.0.0.0/24)' };
  }

  // 192.168.0.0/16 (RFC-1918 Private)
  if (o1 === 192 && o2 === 168) return { isBlocked: true, reason: 'SSRF Block: Private RFC-1918 range (192.168.0.0/16)' };

  // 198.18.0.0/15 (Network Benchmark Testing)
  if (o1 === 198 && (o2 === 18 || o2 === 19)) {
    return { isBlocked: true, reason: 'SSRF Block: Benchmark testing range (198.18.0.0/15)' };
  }

  // 198.51.100.0/24 (TEST-NET-2)
  if (o1 === 198 && o2 === 51) return { isBlocked: true, reason: 'SSRF Block: TEST-NET-2 documentation range' };

  // 203.0.113.0/24 (TEST-NET-3)
  if (o1 === 203 && o2 === 0) return { isBlocked: true, reason: 'SSRF Block: TEST-NET-3 documentation range' };

  // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
  if (o1 >= 224) return { isBlocked: true, reason: 'SSRF Block: Multicast / Reserved address range (>= 224.0.0.0)' };

  return { isBlocked: false };
}

/**
 * SSRF Guard: Validates that an outgoing target URL is safe and not targeting
 * loopback, internal RFC-1918 addresses, cloud metadata endpoints, or private IPv6.
 */
export function validateOutgoingUrl(rawUrl: string): { isValid: boolean; parsedUrl: URL; reason?: string } {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { isValid: false, parsedUrl: {} as URL, reason: 'Malformed URL format' };
  }

  // 1. Protocol Whitelist: Only HTTP and HTTPS
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { isValid: false, parsedUrl: parsed, reason: `Disallowed protocol: '${parsed.protocol}'. Only http: and https: permitted.` };
  }

  // 2. Reject embedded credentials in authority (user:pass@host)
  if (parsed.username || parsed.password) {
    return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: Embedded userinfo credentials in URL authority are prohibited' };
  }

  const rawHostname = parsed.hostname.toLowerCase();
  // Strip IPv6 enclosing brackets if present
  const hostname = rawHostname.replace(/^\[|\]$/g, '');

  // 3. Known Internal and Cloud Metadata Hostnames
  const blockedHostnames = [
    'localhost',
    'metadata.google.internal',
    'metadata',
    'instance-data',
    'internal',
  ];
  if (blockedHostnames.includes(hostname)) {
    return { isValid: false, parsedUrl: parsed, reason: `SSRF Block: Internal/Cloud Metadata hostname ('${hostname}') prohibited` };
  }

  // 4. Block dangerous internal TLDs and suffix patterns
  const internalSuffixes = [
    '.localhost',
    '.local',
    '.internal',
    '.localdomain',
    '.lan',
    '.home',
    '.corp',
  ];
  if (internalSuffixes.some((suffix) => hostname.endsWith(suffix))) {
    return { isValid: false, parsedUrl: parsed, reason: `SSRF Block: Internal network domain suffix prohibited` };
  }

  // 5. Block Cloud Instance Metadata Service patterns anywhere in hostname
  if (/169[.-]254/i.test(hostname)) {
    return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: Cloud Instance Metadata Service pattern prohibited' };
  }

  // 6. Block DNS Wildcard Rebinding Services pointing to private IPs
  if (
    /(?:^|\.)(?:nip\.io|sslip\.io|xip\.io)$/i.test(hostname) &&
    /(?:^|\.|-)(?:127|10|172[.-](?:1[6-9]|2[0-9]|3[01])|192[.-]168|169[.-]254|0[.-]0[.-]0[.-]0)(?:[.-]|$)/.test(hostname)
  ) {
    return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: DNS rebinding service targeting internal IP prohibited' };
  }

  // 6. IPv6 Range Validation
  if (hostname.includes(':')) {
    // IPv6 Loopback: ::1 or 0:0:0:0:0:0:0:1
    if (hostname === '::1' || /^0*(?::0*)*:1$/.test(hostname)) {
      return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: IPv6 Loopback (::1) prohibited' };
    }
    // IPv6 Unspecified: ::
    if (hostname === '::' || /^0*(?::0*)*$/.test(hostname)) {
      return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: IPv6 Unspecified address (::) prohibited' };
    }
    // IPv6 Link-Local (fe80::/10)
    if (/^fe[89ab]/i.test(hostname)) {
      return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: IPv6 Link-Local range (fe80::/10) prohibited' };
    }
    // IPv6 Unique Local (fc00::/7 -> fc.. or fd..)
    if (/^f[cd]/i.test(hostname)) {
      return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: IPv6 Unique Local range (fc00::/7) prohibited' };
    }
    // IPv4-mapped IPv6: ::ffff:127.0.0.1 or ::ffff:7f00:1
    if (hostname.startsWith('::ffff:')) {
      const mappedPart = hostname.slice(7);
      const mappedIpNum = parseIpv4ToNumber(mappedPart);
      if (mappedIpNum !== null) {
        const check = isPrivateOrReservedIpv4(mappedIpNum);
        if (check.isBlocked) {
          return { isValid: false, parsedUrl: parsed, reason: `SSRF Block: IPv4-mapped IPv6 internal target (${check.reason})` };
        }
      } else {
        return { isValid: false, parsedUrl: parsed, reason: 'SSRF Block: Malformed IPv4-mapped IPv6 address prohibited' };
      }
    }
  }

  // 7. IPv4 Range Validation (covers decimal, octal, hex, dword representations)
  const ipv4Num = parseIpv4ToNumber(hostname);
  if (ipv4Num !== null) {
    const check = isPrivateOrReservedIpv4(ipv4Num);
    if (check.isBlocked) {
      return { isValid: false, parsedUrl: parsed, reason: check.reason };
    }
  }

  // 8. Block High-Risk Internal Service Ports
  const port = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === 'https:' ? 443 : 80;
  const dangerousPorts = [
    21, 22, 23, 25, 69, 110, 111, 135, 139, 143, 389, 445, 636,
    1433, 1521, 2375, 2376, 2379, 2380, 3306, 3389, 5000, 5432,
    5900, 6379, 7001, 8080, 8443, 8500, 9200, 9300, 11211, 27017,
  ];
  if (dangerousPorts.includes(port)) {
    return { isValid: false, parsedUrl: parsed, reason: `SSRF Block: High-risk internal service port (${port}) prohibited` };
  }

  return { isValid: true, parsedUrl: parsed };
}
