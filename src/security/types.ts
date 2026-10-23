/**
 * Project Fortress — Security Architecture Core Types
 * @license Apache-2.0
 */

export type ThreatLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type SecurityRole = 'ADMIN' | 'SECOPS' | 'AUDIT' | 'SERVICE' | 'ANONYMOUS';

export type SecurityPermission =
  | 'read:telemetry'
  | 'write:policy'
  | 'execute:remediation'
  | 'read:audit'
  | 'rotate:keys'
  | 'simulate:attack'
  | 'read:system';

export interface SecurityUser {
  id: string;
  username: string;
  role: SecurityRole;
  permissions: SecurityPermission[];
  tenantId: string;
}

export interface SecurityTokenPayload {
  sub: string;
  username: string;
  role: SecurityRole;
  permissions: SecurityPermission[];
  tenantId: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string;
  jti: string;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  eventType: 'AUTH_SUCCESS' | 'AUTH_FAILURE' | 'INJECTION_DETECTED' | 'RATE_LIMITED' | 'CONFIG_VALIDATED' | 'SECRET_ROTATED' | 'ISOLATION_CHECK';
  severity: ThreatLevel;
  sourceIp: string;
  principal: string;
  details: Record<string, unknown>;
  redacted: boolean;
}

export interface SanitizationResult {
  isClean: boolean;
  sanitizedValue: string;
  detectedThreats: Array<{
    type: 'SQLI' | 'NOSQLI' | 'CMD_INJECTION' | 'PATH_TRAVERSAL' | 'SSRF' | 'XSS';
    confidence: 'PROBABLE' | 'DEFINITE';
    matchedPattern: string;
    description: string;
  }>;
}

export interface RateLimitStatus {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetMs: number;
  retryAfterSec?: number;
}

export interface ContainerSecurityProfile {
  runAsNonRoot: boolean;
  uid: number;
  gid: number;
  readOnlyRootFilesystem: boolean;
  allowPrivilegeEscalation: boolean;
  dropCapabilities: string[];
  addCapabilities: string[];
  seccompProfileType: 'RuntimeDefault' | 'CustomWhitelist';
  memoryLimitMb: number;
  cpuLimitCores: number;
}

export interface VerificationCheckResult {
  id: string;
  category: 'CONFIG' | 'INPUT_VALIDATION' | 'AUTH' | 'LOGGING' | 'RATE_LIMIT' | 'ISOLATION' | 'SUPPLY_CHAIN';
  name: string;
  status: 'PASS' | 'FAIL' | 'SKIPPED';
  executionTimeMs: number;
  details: string;
  evidence?: unknown;
}
