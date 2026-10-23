# Project Fortress — Comprehensive Threat Model

**Document Version:** 1.0.0  
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) + Defense-in-Depth  
**Scope:** Reusable cybersecurity infrastructure, runtime risk mitigation, and application gateway  

---

## 1. Objectives and System Boundaries

Project Fortress provides a language-independent, defense-in-depth security infrastructure designed to neutralize vulnerabilities across application runtimes, third-party libraries, container environments, and web services.

### Core Assets Under Protection
1. **Application Secrets & Keys:** API tokens, cryptographic signing keys, database credentials.
2. **System Integrity & Execution Boundaries:** Host kernel, container namespaces, process execution privileges.
3. **Sensitive Data:** User records, audit trail logs, security event telemetry.
4. **Service Availability:** Network throughput, worker CPU/memory resources, database connection pools.

### Threat Actors
- **External Unauthenticated Attackers:** Exploiting public endpoints via automated scanners, injection payloads, or SSRF.
- **Compromised Dependencies:** Malicious or hijacked npm/pip packages injecting backdoor payloads into the build or runtime.
- **Malicious Insiders / Compromised Tenants:** Attempting horizontal privilege escalation (cross-tenant access) or vertical privilege escalation (regular user to root/admin).
- **Network Eavesdroppers & Man-in-the-Middle (MitM):** Intercepting unencrypted traffic or tampering with requests.

---

## 2. Threat Analysis Matrix (STRIDE & Attack Vectors)

### 2.1 Remote Code Execution (RCE) & Memory Safety
- **Attack Vector:** Exploitation of runtime buffer overflows, use-after-free, unvalidated deserialization, or dynamic command invocation (`eval`, `child_process.exec`).
- **Mitigation:**
  - Strict prohibition of dynamic code evaluation and raw shell execution.
  - Deployment on memory-safe, bounds-checked TypeScript/Node.js runtime with strict typing.
  - Process sandboxing: non-root execution (`uid 10001`), dropping all Linux capabilities (`CAP_SYS_ADMIN`, `CAP_NET_RAW`), seccomp syscall filtering, and read-only container root filesystems.
- **Residual Risk:** Zero-day vulnerabilities in the underlying container runtime (e.g., runc) or kernel hypervisor. Mitigated by hosting on microVM / gVisor architectures.

### 2.2 Injection and Unsafe Deserialization
- **Attack Vector:** SQL injection (SQLi), NoSQL query operator injection (`$gt`, `$where`), OS command injection (`|`, `&`, `;`), and prototype pollution via `JSON.parse`.
- **Mitigation:**
  - Centralized input sanitization layer (`src/security/sanitizer.ts`) validating against strict schemas and regex heuristics before hitting business logic.
  - Deep-freeze and `Object.create(null)` defense against prototype pollution.
  - Safe parameterized interfaces; no raw query concatenation permitted.
- **Residual Risk:** Novel, heavily obfuscated payloads bypassing pattern-based detection. Addressed by defense-in-depth: unprivileged database users with strict schema permissions.

### 2.3 Authentication and Authorization Failures
- **Attack Vector:** Broken object-level authorization (BOLA/IDOR), token forgery, expired token acceptance, privilege escalation.
- **Mitigation:**
  - Cryptographically signed HMAC-SHA256 bearer tokens with non-malleable claims (`sub`, `role`, `exp`, `iss`, `aud`).
  - Constant-time signature verification (`crypto.timingSafeEqual`) to prevent timing side-channel attacks.
  - Strict Role-Based Access Control (RBAC) and capability matrices (`ADMIN`, `SECOPS`, `AUDIT`, `SERVICE`, `ANONYMOUS`).
- **Residual Risk:** Key compromise on host. Addressed by cryptographic key rotation interfaces and ephemeral token lifetimes (max 15-60 minutes).

### 2.4 Credential Theft & Secret Leakage
- **Attack Vector:** Printing credentials in application stack traces, committing secrets to Git repositories, or exposing `.env` files via path traversal.
- **Mitigation:**
  - Structured, sanitized logging pipeline (`src/security/logger.ts`) with deterministic redaction for API keys, bearer tokens, passwords, JWTs, and private keys.
  - Automated pre-flight secret scanner in the security verification pipeline.
  - Secure error handling (`src/security/errors.ts`) ensuring internal stack traces and environment variables never reach API clients.
- **Residual Risk:** Novel secret patterns not matched by regex or entropy filters.

### 2.5 Software Supply Chain & Dependency Compromise
- **Attack Vector:** Malicious code introduced through compromised third-party package releases (typosquatting, account hijacking).
- **Mitigation:**
  - Dependency pinning in `package.json` with strict `package-lock.json` hash integrity verification.
  - Minimal dependency footprint (zero runtime dependencies for core security validators; reliance on native Node.js `crypto`).
  - Automated `npm audit` and vulnerability scanning integrated into CI pipeline.
- **Residual Risk:** Zero-day malicious packages introduced before public advisory disclosure.

### 2.6 Server-Side Request Forgery (SSRF)
- **Attack Vector:** Inducing the server to make requests to internal services, loopback interfaces (`127.0.0.1`), link-local metadata addresses (`169.254.169.254`), or private RFC-1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Mitigation:**
  - Dedicated SSRF guard (`validateOutgoingUrl`) validating URL protocols (`http`/`https` only), resolving hostnames, and rejecting private/loopback/cloud metadata IP ranges.
  - Disallowing internal port scanning and redirect following to private destinations.
- **Residual Risk:** DNS rebinding attacks where a public DNS record alternates between an external IP and an internal IP. Mitigated by re-validating the resolved IP at socket connect time.

### 2.7 Cross-Site Scripting (XSS) and Content Security
- **Attack Vector:** Reflected, stored, or DOM-based XSS injecting malicious JavaScript into user browser sessions.
- **Mitigation:**
  - Context-aware HTML entity encoding on all user-supplied outputs.
  - Strict Content Security Policy (CSP) headers disallowing inline script execution (`'unsafe-inline'`), restricting object sources, and enforcing HTTPS.
  - Modern React component rendering which automatically encodes JSX expressions.
- **Residual Risk:** Third-party widgets or client-side libraries manipulating `innerHTML`. Mitigated by strict static code analysis checks.

### 2.8 Denial of Service (DoS) and Resource Exhaustion
- **Attack Vector:** High-volume traffic floods, algorithmic complexity attacks (ReDoS), or memory starvation via huge payload submissions.
- **Mitigation:**
  - Dual-tier rate limiting: Token bucket and sliding-window rate limiters per IP / client token.
  - Request body size limits (bounded JSON parsing, max 1MB).
  - Explicit execution timeouts on synchronous and asynchronous operations.
- **Residual Risk:** Distributed denial-of-service (DDoS) overwhelming network bandwidth before reaching application gateway. Requires upstream edge DDoS mitigation (e.g., Cloudflare, Cloud Armor).

---

## 3. Trust Boundaries

```
[ Untrusted Public Internet ]
          │
          ▼
   [ Boundary 1: Edge TLS & Reverse Proxy ] (TLS termination, IP rate limiting)
          │
          ▼
   [ Boundary 2: Fortress Security Gateway ]
     ├─ Input Sanitizer (SQLi, NoSQLi, SSRF, XSS filter)
     ├─ Rate Limiting (Token Bucket)
     ├─ Authentication & Token Verification (HMAC-SHA256)
     ├─ Policy Engine & RBAC Enforcement
          │
          ▼
   [ Boundary 3: Core Application Business Logic ] (Memory-Safe TypeScript)
          │
          ▼
   [ Boundary 4: Data & Secrets Storage ] (Encrypted-at-rest, envelope encryption)
          │
          ▼
   [ Boundary 5: Host OS & Container Runtime ] (Non-root UID 10001, Seccomp, Read-only FS)
```

---

## 4. Verification & Testing Strategy
Every identified threat has a corresponding automated test in `tests/`:
1. `tests/config.test.ts` — Insecure configuration rejection.
2. `tests/sanitizer.test.ts` — SQLi, NoSQLi, Command Injection, Path Traversal, and SSRF rejection.
3. `tests/auth.test.ts` — Token tampering, expired credentials, and RBAC boundary enforcement.
4. `tests/logger.test.ts` — Deterministic secret redaction in logs and errors.
5. `tests/rateLimiter.test.ts` — Rate limiting and burst threshold enforcement.
6. `tests/isolation.test.ts` — Container profile, capability dropping, and least privilege verification.
7. `tests/pipeline.test.ts` — Automated end-to-end security pipeline verification.
