/**
 * Project Fortress — Runtime & Service Isolation Subsystem
 * @license Apache-2.0
 */

import { ContainerSecurityProfile } from './types.ts';
import { ValidationError } from './errors.ts';

export const PRODUCTION_HARDENED_PROFILE: ContainerSecurityProfile = {
  runAsNonRoot: true,
  uid: 10001,
  gid: 10001,
  readOnlyRootFilesystem: true,
  allowPrivilegeEscalation: false,
  dropCapabilities: [
    'ALL',
    'CAP_SYS_ADMIN',
    'CAP_NET_RAW',
    'CAP_NET_ADMIN',
    'CAP_SYS_PTRACE',
    'CAP_DAC_OVERRIDE',
    'CAP_FOWNER',
    'CAP_MKNOD',
  ],
  addCapabilities: [],
  seccompProfileType: 'CustomWhitelist',
  memoryLimitMb: 512,
  cpuLimitCores: 1.0,
};

export interface IsolationAuditResult {
  isCompliant: boolean;
  scorePercent: number;
  checks: Array<{
    rule: string;
    passed: boolean;
    severity: 'HIGH' | 'CRITICAL' | 'MEDIUM';
    recommendation: string;
  }>;
}

/**
 * Audits a given container / runtime isolation profile against CIS Docker and K8s Restricted PSS standards.
 */
export function auditContainerIsolation(profile: ContainerSecurityProfile): IsolationAuditResult {
  const checks = [
    {
      rule: 'NON_ROOT_EXECUTION',
      passed: profile.runAsNonRoot && profile.uid !== 0 && profile.gid !== 0,
      severity: 'CRITICAL' as const,
      recommendation: 'Ensure container executes under non-root UID (e.g. 10001) with runAsNonRoot=true.',
    },
    {
      rule: 'NO_PRIVILEGE_ESCALATION',
      passed: !profile.allowPrivilegeEscalation,
      severity: 'CRITICAL' as const,
      recommendation: 'Set allowPrivilegeEscalation=false to prevent setuid binaries from gaining root.',
    },
    {
      rule: 'READ_ONLY_ROOT_FILESYSTEM',
      passed: profile.readOnlyRootFilesystem,
      severity: 'HIGH' as const,
      recommendation: 'Mount root filesystem as read-only. Use memory-backed tmpfs for ephemeral writes.',
    },
    {
      rule: 'CAPABILITIES_DROPPED',
      passed:
        profile.dropCapabilities.includes('ALL') ||
        (profile.dropCapabilities.includes('CAP_SYS_ADMIN') &&
          profile.dropCapabilities.includes('CAP_NET_RAW')),
      severity: 'CRITICAL' as const,
      recommendation: 'Drop all Linux capabilities (cap_drop: ALL) to prevent container escape exploits.',
    },
    {
      rule: 'SECCOMP_FILTERING',
      passed: profile.seccompProfileType !== 'RuntimeDefault',
      severity: 'HIGH' as const,
      recommendation: 'Use custom whitelist seccomp profile blocking ptrace, bpf, and kexec.',
    },
    {
      rule: 'RESOURCE_BOUNDS_ENFORCED',
      passed: profile.memoryLimitMb > 0 && profile.memoryLimitMb <= 1024 && profile.cpuLimitCores > 0,
      severity: 'MEDIUM' as const,
      recommendation: 'Enforce explicit cgroup CPU and memory limits to prevent host resource starvation.',
    },
  ];

  const passedCount = checks.filter((c) => c.passed).length;
  const scorePercent = Math.round((passedCount / checks.length) * 100);
  const isCompliant = checks.every((c) => c.passed || c.severity === 'MEDIUM');

  return {
    isCompliant,
    scorePercent,
    checks,
  };
}

/**
 * Validates that an isolation profile meets minimum requirements; throws on critical non-compliance.
 */
export function assertStrictIsolation(profile: ContainerSecurityProfile): void {
  const audit = auditContainerIsolation(profile);
  const criticalFails = audit.checks.filter((c) => !c.passed && c.severity === 'CRITICAL');
  if (criticalFails.length > 0) {
    throw new ValidationError(
      `Strict isolation violation: ${criticalFails.map((f) => f.rule).join(', ')}`
    );
  }
}
