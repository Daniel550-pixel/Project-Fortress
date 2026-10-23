# Project Fortress — Secure Development Lifecycle (SDL) Checklist

**Document Version:** 1.0.0  
**Framework Alignment:** NIST SP 800-218 (SSDF v1.1) • OWASP SAMM v2.0 • ISO/IEC 27034  
**Classification:** Engineering Security Standard & Mandatory Quality Gate  
**Target Audience:** Security Architects, Product Engineers, DevSecOps, SRE  

---

## 1. Executive Overview

This Secure Development Lifecycle (SDL) checklist defines the mandatory security controls, validation activities, ownership, and sign-off gates across each phase of the engineering lifecycle within **Project Fortress**. Every feature, infrastructure update, or external integration must clear its respective security gate before progressing to the next stage.

```
┌─────────────────┐     ┌──────────────┐     ┌────────────────┐     ┌─────────────┐     ┌────────────────┐     ┌────────────────┐
│ 1. REQUIREMENTS │ ──► │  2. DESIGN   │ ──► │ 3. IMPLEMENT.  │ ──► │ 4. TESTING  │ ──► │ 5. DEPLOYMENT  │ ──► │ 6. OPERATIONS  │
└─────────────────┘     └──────────────┘     └────────────────┘     └─────────────┘     └────────────────┘     └────────────────┘
```

---

## 2. Phase 1 — Security Requirements

**Objective:** Identify regulatory, privacy, and technical security requirements before architectural work begins.

| Activity ID | Required Activity | Mandatory Artifact / Evidence | Owner | Gate Status |
|---|---|---|---|---|
| **REQ-01** | **Data Classification & Handling:** Identify data tiers (Public, Internal, Confidential, Restricted/Sovereign). Establish encryption at rest and in transit requirements. | Data Classification Matrix | Security Architect | Mandatory |
| **REQ-02** | **Threat Profile & Compliance Baseline:** Map feature scope against NIST SP 800-53, CIS Benchmarks, and local sovereign data residency mandates. | Regulatory Baseline Doc | Lead Architect | Mandatory |
| **REQ-03** | **Identity & Authorization Scope:** Define required roles (`ADMIN`, `SECOPS`, `AUDIT`, `SERVICE`, `ANONYMOUS`) and minimum required capabilities per endpoint. | Capability Mapping Spec | SecOps Lead | Mandatory |
| **REQ-04** | **Service SLA & Abuse Thresholds:** Establish expected RPS, burst capacity limits, rate-limiting windows, and maximum request payload sizes. | Rate Limit Definition | Performance/SRE | Mandatory |

---

## 3. Phase 2 — Secure Architecture & Design

**Objective:** Eliminate structural vulnerabilities and design flaws before writing production code.

| Activity ID | Required Activity | Mandatory Artifact / Evidence | Owner | Gate Status |
|---|---|---|---|---|
| **DES-01** | **STRIDE Threat Modeling:** Conduct STRIDE threat analysis covering Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege. | `docs/THREAT_MODEL.md` update | Security Architect | Mandatory |
| **DES-02** | **Trust Boundary Delineation:** Explicitly diagram network ingress, container namespaces, database connections, and third-party API boundaries. | Component Topology Diagram | System Architect | Mandatory |
| **DES-03** | **Cryptographic Architecture Review:** Validate algorithm choices (e.g. HMAC-SHA256, AES-256-GCM, Ed25519). Zero custom crypto primitives permitted. | Cryptographic Spec Sheet | Cryptography Reviewer | Mandatory |
| **DES-04** | **SSRF & Egress Architecture:** Define outbound destination whitelists; disallow access to RFC-1918 subnets and cloud metadata (`169.254.169.254`). | Egress Firewall Matrix | Network/SecOps | Mandatory |
| **DES-05** | **Failure Mode & Fail-Closed Analysis:** Verify that all unexpected crashes, timeouts, and unhandled rejections result in safe denial without leaking internal state. | Failure Matrix Analysis | Lead Engineer | Mandatory |

---

## 4. Phase 3 — Secure Implementation & Coding

**Objective:** Write memory-safe, vulnerability-resistant source code adhering to defensive programming standards.

| Activity ID | Required Activity | Mandatory Artifact / Evidence | Owner | Gate Status |
|---|---|---|---|---|
| **IMP-01** | **Strict Typing & Bounds Checking:** Compile with strict TypeScript (`"strict": true`, `"isolatedModules": true`, `"noEmit": true`). No `any` type escapes. | Clean `npm run lint` | Software Engineer | Mandatory |
| **IMP-02** | **Parameterized Data Access:** Zero string concatenation or template literals for SQL, NoSQL, or shell command execution. | Static AST Analysis | Software Engineer | Mandatory |
| **IMP-03** | **Deterministic Secret Redaction:** Route all log outputs through `src/security/logger.ts` to redact JWTs, bearer tokens, AWS keys, and passwords. | Log Sanitization Review | Software Engineer | Mandatory |
| **IMP-04** | **Constant-Time Verification:** Use `timingSafeEqualString` for all token, signature, and cryptographic hash comparisons. | Code Inspection | Peer Reviewer | Mandatory |
| **IMP-05** | **Zero Hardcoded Credentials:** Inject secrets strictly through environment variables or KMS vaults. Never commit secrets to Git. | Automated Secret Scan | DevSecOps | Mandatory |
| **IMP-06** | **Dependency Minimization & Pinning:** Rely on native Node.js libraries (`node:crypto`, `node:test`). Pin all dependencies in `package-lock.json`. | Verified Lockfile | Lead Engineer | Mandatory |

---

## 5. Phase 4 — Security Verification & Testing

**Objective:** Programmatically prove resistance to attacks and verify that security controls enforce policy.

| Activity ID | Required Activity | Command / Tool | Owner | Gate Status |
|---|---|---|---|---|
| **TST-01** | **Automated Unit & Regression Suite:** Execute test suite covering injection, token tampering, and ReDoS resilience. | `npm test` (All 29 tests pass) | Test Engineer | Mandatory |
| **TST-02** | **Automated Security Pipeline:** Run end-to-end 14-point verification pipeline with zero failures. | `npm run security:verify` | CI Pipeline / SecOps | Mandatory |
| **TST-03** | **Dependency Vulnerability Scan:** Scan dependency tree for known vulnerabilities with High/Critical severity. | `npm run security:audit` (0 CVEs) | DevSecOps | Mandatory |
| **TST-04** | **Fuzzing & Payload Mutation:** Test input sanitizers with polymorphic SQLi, NoSQL operators, and cloud metadata SSRF vectors. | `tests/sanitizer.test.ts` | Security Tester | Mandatory |
| **TST-05** | **Race Condition & Rate Limit Testing:** Verify token bucket depletion and recovery under simulated concurrency spikes. | `tests/rateLimiter.test.ts` | QA Engineer | Mandatory |

---

## 6. Phase 5 — Secure Deployment & Container Hardening

**Objective:** Ensure application executes in an unprivileged, isolated sandbox with minimal attack surface.

| Activity ID | Required Activity | Verification Standard | Owner | Gate Status |
|---|---|---|---|---|
| **DEP-01** | **Non-Root Execution:** Container runs strictly as unprivileged user (`UID 10001`, `GID 10001`). `runAsNonRoot: true`. | CIS Docker 4.1 | Platform Engineer | Mandatory |
| **DEP-02** | **Read-Only Root Filesystem:** Root filesystem mounted read-only (`readOnlyRootFilesystem: true`). Ephemeral storage via `tmpfs`. | CIS Docker 5.12 | Platform Engineer | Mandatory |
| **DEP-03** | **Capability Dropping:** Drop all Linux kernel capabilities (`cap_drop: ALL`). Zero setuid escalation allowed. | CIS Docker 5.13 | Platform Engineer | Mandatory |
| **DEP-04** | **Syscall Sandboxing:** Enforce custom whitelist seccomp profile (`deploy/seccomp-profile.json`) blocking `ptrace`, `bpf`, `kexec`. | Linux Seccomp Spec | Platform Engineer | Mandatory |
| **DEP-05** | **Resource Quotas & cgroups:** Enforce hard CPU (1.0 core) and memory (512MB) limits to prevent DoS by starvation. | Kubernetes PSS / Docker | SRE / Platform | Mandatory |
| **DEP-06** | **Minimal Base Image:** Utilize distroless or minimal slim images stripped of curl, wget, python, and shell compilers. | Image Scan Analysis | DevSecOps | Mandatory |

---

## 7. Phase 6 — Operations, Observability & Incident Response

**Objective:** Maintain continuous security monitoring, key rotation, and rapid incident containment in production.

| Activity ID | Required Activity | Frequency / Trigger | Owner | Gate Status |
|---|---|---|---|---|
| **OPS-01** | **Health Probes Without Data Leak:** Expose `/api/health` returning operational status without environment or software version disclosures. | Continuous (Every 30s) | SRE | Mandatory |
| **OPS-02** | **Cryptographic Key Rotation:** Rotate HMAC signing keys and AES-256-GCM envelope master keys. | Every 90 Days or Incident | SecOps Lead | Mandatory |
| **OPS-03** | **Audit Log Centralization:** Ingest sanitized structured JSON security events into append-only SIEM / log storage. | Real-Time Streaming | SOC Analyst | Mandatory |
| **OPS-04** | **Incident Response Readiness:** Exercise CIRT containment, token revocation, and pod isolation procedures. | Biannual Drill | CIRT Commander | Mandatory |
| **OPS-05** | **Regression Commit Policy:** Commit an automated regression test into `tests/regression.test.ts` for every remediated finding. | Upon Every Patch | Lead Engineer | Mandatory |

---

## 8. Release Sign-Off Signatures

| Gate Phase | Approver Role | Verification Artifact | Signature Status |
|---|---|---|---|
| **Phase 1: Requirements** | Principal Architect | Threat Profile & Spec | APPROVED |
| **Phase 2: Design** | Security Architect | STRIDE Model & Egress Policy | APPROVED |
| **Phase 3: Implementation**| Tech Lead | Strict TypeScript & Linting | APPROVED |
| **Phase 4: Testing** | Lead Test Engineer | 100% Pass on Security Suite | APPROVED |
| **Phase 5: Deployment** | DevSecOps Lead | CIS Docker / K8s Restricted Audit | APPROVED |
| **Phase 6: Operations** | SRE Commander | Non-leaking Health Probe & Key SOP | APPROVED |
