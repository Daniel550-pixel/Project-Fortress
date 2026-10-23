# Project Fortress — Security Policy & Vulnerability Disclosure

**Effective Date:** 2026-10-23  
**Status:** Active  

---

## 1. Reporting a Vulnerability

The Project Fortress engineering team treats security vulnerabilities with the highest priority. If you discover a potential security flaw, vulnerability, or bypass in any component, please follow responsible disclosure:

- **Primary Contact:** `security@fortress.internal` or via the designated secure communications channel.
- **PGP Encryption:** Encrypt all vulnerability details using the Project Fortress Security Team PGP public key.
- **Information to Include:**
  - Description of the vulnerability and attack vector.
  - Minimal reproducible proof-of-concept (PoC) using harmless test payloads.
  - Expected vs actual behavior.
  - Impact assessment (confidentiality, integrity, availability).

*Please do NOT create public issues or disclose technical details publicly until coordinated disclosure is completed.*

---

## 2. Scope

### In Scope
- Core security controls: `src/security/*` (sanitization, auth, rate-limiting, logging, secrets, isolation).
- Container deployment configurations: `deploy/*` (Dockerfile, seccomp, Kubernetes manifests).
- Automated verification pipelines: `scripts/security-verify.ts` and automated test suites.

### Out of Scope
- Denial of service attacks against third-party upstream DNS providers.
- Attacks requiring physical device access or compromising the client's local workstation.
- Social engineering against personnel.

---

## 3. Vulnerability Triage and SLA

| Severity | Initial Response | Remediation & Patch Release |
|---|---|---|
| **Critical** | < 4 hours | < 24 hours |
| **High** | < 12 hours | < 72 hours |
| **Medium** | < 24 hours | < 7 business days |
| **Low** | < 48 hours | Next scheduled maintenance release |

---

## 4. Security Commitments
- **Zero Insecure Defaults:** All security flags default to strict enforcement.
- **Regression Assurance:** Every remediated vulnerability receives a permanent automated test in `tests/regression.test.ts`.
- **Transparency:** Fixed security advisories are documented with CVE IDs and mitigation guidance.
