# Project Fortress — Secure Development Guidelines

**Document Version:** 1.0.0  
**Target Audience:** Core Contributors and Security Engineers  

---

## 1. Secure Coding Standards

1. **Zero Raw SQL / NoSQL Concat:** Never concatenate untrusted strings into database queries or shell commands. Always use parameterized queries or the input sanitizer (`src/security/sanitizer.ts`).
2. **Fail-Closed Principle:** Exception handlers must default to rejecting access. Never catch an error and return an unverified default payload.
3. **No Dynamic Execution:** The use of `eval()`, `new Function()`, `setTimeout(string)`, or `child_process.exec(rawString)` is strictly forbidden and blocked by compiler and static analysis rules.
4. **Leak-Proof Logging:** Always pipe log statements through `securityLogger.log()` or `redactSensitiveData()`. Never call raw `console.log` on request headers, user records, or error objects containing stack traces.
5. **Constant-Time Cryptography:** When comparing cryptographic signatures, hashes, or bearer tokens, always use `timingSafeEqualString()` to prevent timing side-channel attacks.

---

## 2. Pre-Commit Verification Checklist

Before submitting code, execute the following mandatory local commands:

```bash
# 1. Type check and static analysis
npm run lint

# 2. Execute all unit and integration security tests
npm test

# 3. Run automated security verification pipeline
npm run security:verify

# 4. Audit dependencies
npm run security:audit
```

---

## 3. Dependency Hygiene Policy

- **Lockfile Integrity:** `package-lock.json` must be committed and verified with `--ignore-scripts` during CI builds.
- **Minimal Dependencies:** Prioritize native Node.js / ECMAScript APIs over third-party packages. Avoid single-function micro-packages (e.g., `is-odd`, `left-pad`).
- **Zero High/Critical Vulnerabilities:** Any pull request introducing dependencies with known High or Critical CVEs is automatically blocked.
