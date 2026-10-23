# Project Fortress — Incident Response Playbook

**Document Reference:** CIRT-SOP-001  
**Classification:** Operational Security Response  
**Version:** 1.0.0  

---

## 1. Incident Severity Classification

| Severity Level | Criteria | Required Response SLA |
|---|---|---|
| **P1 - CRITICAL** | Active RCE attempt, master key leakage, widespread bypass of authentication | Immediate (< 15 minutes) |
| **P2 - HIGH** | Exploitable SSRF attempt, targeted privilege escalation, repeatable DoS attack | < 1 hour |
| **P3 - MEDIUM** | Anomalous input bursts blocked by rate limiter, non-exploitable injection scanner | < 8 hours |
| **P4 - LOW** | Transient health probe timeouts, benign port scan against reverse proxy | < 24 hours |

---

## 2. Six-Phase Response Workflow (NIST SP 800-61 Rev. 2)

```
[ 1. Preparation ] ──► [ 2. Detection & Analysis ] ──► [ 3. Containment ]
                                                                │
[ 6. Post-Incident Review ] ◄── [ 5. Recovery ] ◄── [ 4. Eradication ]
```

### Phase 1: Preparation
- Audit logging enabled with deterministic redaction in `src/security/logger.ts`.
- Pre-allocated emergency break-glass credentials.
- Container isolation profiles pre-deployed with dropped capabilities.

### Phase 2: Detection and Analysis
1. Inspect audit logs for `INJECTION_DETECTED`, `AUTH_FAILURE`, or `RATE_LIMITED` events:
   - Identify source IP address, target endpoint, and attack pattern.
2. Verify whether any payload bypassed initial filtering into application logic.
3. Determine if tokens issued to affected user identities were observed in anomalous locations.

### Phase 3: Containment
- **IP-Level Null-Routing:** Drop traffic from offending IP CIDR blocks at edge firewall / reverse proxy.
- **Session Revocation:** Trigger immediate blacklisting of compromised `jti` token IDs.
- **Micro-Isolation:** If an application worker shows signs of container compromise, immediately isolate the pod from Kubernetes network policies (`egress: []`).

### Phase 4: Eradication
- Perform immediate emergency cryptographic key rotation using `SecretManager.rotateKey()`.
- Invalidate all active bearer tokens across all tenants.
- Deploy patched code with new regression tests added to `tests/regression.test.ts`.

### Phase 5: Recovery
- Deploy fresh container instances built from immutable, signed images.
- Restore normal traffic routing through the Fortress Security Gateway.
- Confirm 0% packet loss and 100% pass rate on health probes (`/api/health`).

### Phase 6: Post-Incident Review (Lessons Learned)
- Conduct blameless root-cause analysis (RCA) within 72 hours.
- Document exact vulnerability reproduction in `reports/`.
- Ensure new regression tests are committed to continuous integration.
