# Project Fortress — Technology Stack Evaluation & Architectural Decision Record (ADR)

**Document Reference:** ADR-001  
**Status:** Approved  
**Decision Date:** 2026-10-23  

---

## 1. Context and Problem Statement

The concentration of web infrastructure across single language ecosystems introduces systemic risks. When evaluating the implementation stack for Project Fortress, three candidate technologies were analyzed:
1. **Rust**
2. **Go**
3. **TypeScript / Node.js (Strict Mode)**

The goal is to select an implementation stack providing memory safety, strong typing, low attack surface, rapid verifiability, and native integration with the host deployment environment.

---

## 2. Comparative Evaluation Matrix

| Criterion | Rust | Go | TypeScript / Node.js (Strict) |
|---|---|---|---|
| **Memory Safety** | Native borrow checker; zero-cost safety; eliminates UAF & buffer overflow | Garbage-collected memory safety; potential data races if uncoordinated | Garbage-collected memory safety; bounds-checked typed arrays; no raw pointers |
| **Ecosystem & Tooling** | `cargo audit`, Clippy; steep compilation times; complex FFI | `govulncheck`, built-in race detector, fast compilation | Built-in `node:test`, `npm audit`, native Web Crypto, `tsx` instant runtime |
| **Operational Complexity** | High cognitive overhead; longer iteration loops; native binary distribution | Low cognitive overhead; single static binary | Low cognitive overhead; cross-platform bytecode/JIT; ubiquitous runtime |
| **Dependency Risk** | Cargo crate dependencies can be deeply nested; macro compilation risk | Minimalist standard library reduces external dependencies | `node_modules` ecosystem can be bloated; mitigated by zero external deps for core security logic |
| **Host Tool Availability** | Not available in current container environment | Not available in current container environment | Fully installed, configured, and verified (`node v22.23.3`, `npm 10.9.9`, `tsx 4.23.15`) |
| **Interactive Observability** | Requires external UI / WebAssembly bridge | Requires external web template engine or separate SPA | Native full-stack unified runtime with React 19 UI dashboard |

---

## 3. Decision Rationale

### Selection: TypeScript (Strict ESM) on Node.js v22 LTS with Built-in Standard Libraries

**Key Justifications:**
1. **Host Alignment and Verifiability:** The target runtime environment natively provides Node.js 22 LTS, npm, and `tsx`. Rust and Go compilers are absent in the local host container. Attempting to cross-compile or fabricate external binaries would violate our verifiable execution policy.
2. **Memory Safety Without Native Undefined Behavior:** TypeScript compiled under strict ESM runs within V8's sandbox. It is immune to conventional C-style memory corruption bugs (stack buffer overflows, use-after-free, double frees, format string exploits) while avoiding the operational friction of unmanaged runtimes.
3. **Zero-Dependency Security Core:** Core security modules (`crypto`, `sanitizer`, `auth`, `rateLimiter`, `logger`, `isolation`) are implemented utilizing native Node.js and standard ECMAScript APIs (`node:crypto`, `node:test`, `node:assert`). No risky third-party packages are introduced for cryptographic algorithms or fundamental policy enforcement.
4. **Unified Control Plane:** Allows the security gateway, verification engine, automated test suite, and interactive Security Operations Center (SOC) dashboard to execute seamlessly in a single coherent codebase.

---

## 4. Architectural Safeguards Applied to Selected Stack

Because memory safety is not a substitute for application-layer security, TypeScript is deployed with defense-in-depth controls:
- Strict Compiler Flags: `"strict": true`, `"isolatedModules": true`, `"noEmit": true`.
- Native Cryptography: Zero custom cryptographic primitives; strict usage of `crypto.timingSafeEqual` and `crypto.createHmac`.
- Prototype Pollution Defense: Strict sanitization and object isolation using `Object.freeze` and prototype validation.
- Resource Bounds: Bounded JSON parsing, request timeouts, and token bucket rate limiters to mitigate V8 event-loop starvation.
- Container Hardening: Non-root execution (`uid 10001`), seccomp syscall filtering, and read-only container rootfs.
