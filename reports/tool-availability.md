# Project Fortress — Tool Availability Matrix

**Date of Execution:** 2026-10-23  
**Status:** Verified  
**Scope:** Build tools, compilers, test frameworks, security scanners, and container utilities.

---

## 1. Toolchain Audit Summary

| Tool / Facility | Path / Version | Availability Status | Usage in Project Fortress |
|---|---|---|---|
| **Node.js** | `/usr/local/bin/node` (v22.23.3) | **Available (Verified)** | Core runtime for security infrastructure and API engine |
| **npm** | `/usr/local/bin/npm` (10.9.9) | **Available (Verified)** | Package management, scripts, dependency locking |
| **tsx** | `npx tsx` (v4.23.15) | **Available (Verified)** | TypeScript runtime execution and `node:test` runner |
| **TypeScript (tsc)** | `node_modules/.bin/tsc` (7.0.2) | **Available (Verified)** | Static type checking and strict compiler validation |
| **Python 3** | `/usr/bin/python3` (3.11.2) | **Available (Verified)** | System scripts and complementary verification checks |
| **Git** | `/usr/bin/git` (2.34.1) | **Available (Verified)** | Source control and change inspection |
| **Docker / Podman** | N/A (Sandboxed container host) | **Unavailable (Host Limitation)** | Deployment profiles, Seccomp configs, and OCI specs implemented as declarative artifacts |
| **Rust / Cargo** | N/A | **Unavailable** | Evaluated in Technology Decision; TypeScript/Node selected |
| **Go** | N/A | **Unavailable** | Evaluated in Technology Decision; TypeScript/Node selected |
| **GCC / Clang** | N/A | **Unavailable** | No native C/C++ compilation in build environment |
| **Node Test Runner** | Built-in `node:test` + `node:assert/strict` | **Available (Verified)** | Primary unit and integration security test suite |
| **Vite** | `node_modules/.bin/vite` (8.3.0) | **Available (Verified)** | Interactive Security Operations Center UI |

---

## 2. Security Scanners & Verification Capabilities

1. **Dependency Audit:** Handled via `npm audit` and custom lockfile integrity analyzer.
2. **Secret Scanner:** In-house deterministic regex and Shannon entropy scanner (`src/security/pipeline.ts`) covering AWS keys, JWTs, private keys, API secrets, and Bearer tokens.
3. **Static Security Analysis:** TypeScript compiler in strict mode (`--noEmit`) + custom AST / pattern rules for unsafe deserialization, dynamic eval, and unescaped HTML injections.
4. **Input Validation Suite:** Dedicated security testing suite verifying rejection of SQL injection, NoSQL operator injection, command execution, path traversal, and SSRF against RFC-1918 / cloud metadata targets.
5. **Runtime Isolation Profiles:** Dockerfile (unprivileged user 10001, read-only rootfs), Linux Seccomp whitelist, and Kubernetes Restricted Pod Security Standard manifests.
