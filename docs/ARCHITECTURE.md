# Project Fortress — Architecture Specification

**Document Version:** 1.0.0  
**Classification:** Core Engineering Architecture  
**Status:** Approved & Implemented  

---

## 1. Architectural Philosophy

Project Fortress is architected on five foundational tenets:

1. **Language & Runtime Independence:** Core security policies (sanitization, RBAC, rate-limiting, secret redaction, isolation) are defined through canonical specifications, test fixtures, and modular contracts that can be implemented across any modern runtime.
2. **Defense-in-Depth:** Security controls are layered across network, application gateway, runtime process, and data tiers. No single barrier is considered infallible.
3. **Fail-Closed by Default:** Any validation error, missing signature, unhandled exception, or ambiguous configuration defaults to access denial and secure termination.
4. **Zero-Trust Privilege Boundary:** Every inter-service request and user action must carry authenticated, cryptographically verifiable claims with explicit capability grants.
5. **Radical Auditability:** All security-relevant actions, policy rejections, rate violations, and token issuance generate structured, sanitized audit telemetry.

---

## 2. Component Topology

The architecture consists of six tightly integrated but decoupled subsystems:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        PROJECT FORTRESS ENGINE                         │
├────────────────────────────────────────────────────────────────────────┤
│ 1. CONFIGURATION & SECRETS SUBSYSTEM (`src/security/config.ts`, `secrets.ts`)│
│    - Environment variable parsing with strict Zod/TypeScript schemas  │
│    - Disallow dangerous defaults; mandatory encryption key lengths    │
│    - Envelope encryption abstraction & simulated memory zeroization    │
├────────────────────────────────────────────────────────────────────────┤
│ 2. INPUT SANITIZATION & SSRF GUARD (`src/security/sanitizer.ts`)       │
│    - Context-aware validation for SQL, NoSQL, Shell, Path Traversal    │
│    - SSRF Guard: Protocol enforcement & RFC-1918 / Cloud Metadata block│
├────────────────────────────────────────────────────────────────────────┤
│ 3. AUTHENTICATION & ACCESS CONTROL (`src/security/auth.ts`, `boundaries.ts`)│
│    - Constant-time HMAC-SHA256 signature verification                  │
│    - Role-Based Access Control (RBAC) & capability verification        │
│    - Expiration & replay defense                                       │
├────────────────────────────────────────────────────────────────────────┤
│ 4. RATE LIMITING & TRAFFIC PROTECTION (`src/security/rateLimiter.ts`)  │
│    - Dual-tier Token Bucket & Sliding Window algorithms                │
│    - Graceful 429 response handling with retry-after headers           │
├────────────────────────────────────────────────────────────────────────┤
│ 5. OBSERVABILITY & REDACTION (`src/security/logger.ts`, `errors.ts`)   │
│    - Structured JSON audit log stream                                  │
│    - Deterministic redaction engine (Keys, JWTs, Passwords, PII)       │
│    - Leak-proof error taxonomy (Internal pointers scrubbed)            │
├────────────────────────────────────────────────────────────────────────┤
│ 6. RUNTIME ISOLATION & VERIFICATION (`src/security/isolation.ts`, `pipeline.ts`)│
│    - Seccomp whitelist, dropped Linux capabilities                     │
│    - Non-root UID 10001, Read-only filesystem enforcement              │
│    - Automated verification test runner & health monitors              │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Request Flow Lifecycle

Every inbound request passes through the **Fortress Security Pipeline**:

```
Client Inbound Request
       │
       ▼
[ Step 1: Rate Limiter ] ─── (Exceeded) ───► [ 429 Too Many Requests ]
       │ (Allowed)
       ▼
[ Step 2: Content-Length & Body Bound ] ─── (Oversized) ───► [ 413 Payload Too Large ]
       │ (Bounded)
       ▼
[ Step 3: Input Sanitizer & Attack Detector ] ─── (Attack Detected) ───► [ Log Incident & 400 Bad Request ]
       │ (Clean)
       ▼
[ Step 4: Authentication & Token Verifier ] ─── (Invalid/Expired) ───► [ 401 Unauthorized ]
       │ (Valid Token)
       ▼
[ Step 5: Authorization & RBAC Policy ] ─── (Insufficient Role) ───► [ 403 Forbidden ]
       │ (Authorized)
       ▼
[ Step 6: Application Logic Execution ]
       │
       ▼
[ Step 7: Output Sanitization & Structured Audit Log ]
       │
       ▼
Secure Response to Client
```

---

## 4. Runtime & Container Isolation Architecture

To mitigate systemic risks from underlying language runtimes, container images are hardened according to the **CIS Docker Benchmark** and **Kubernetes Restricted Pod Security Standard**:

1. **Non-Root Execution:** The application executes under dedicated user `fortress` (`UID 10001`, `GID 10001`).
2. **Capability Dropping:** All Linux capabilities are explicitly dropped (`cap_drop: ALL`). No `CAP_SYS_ADMIN` or raw network socket manipulation is permitted.
3. **Read-Only Root Filesystem:** Root filesystem is mounted read-only (`read_only: true`). Temporary state is restricted to a memory-backed tmpfs (`/tmp`) with `noexec,nosuid,nodev` flags.
4. **Syscall Filtering (Seccomp):** Default-deny seccomp profile whitelisting only essential POSIX syscalls (`read`, `write`, `epoll_wait`, `gettimeofday`, `nanosleep`), blocking dangerous calls like `ptrace`, `bpf`, and `kexec_load`.
5. **Resource Constraints:** Hard limits on CPU quotas (1.0 core) and memory allocations (512MB max) enforced via cgroups v2 to neutralize memory-leak and fork-bomb DoS attacks.
