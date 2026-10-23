# Project Fortress — Operational Runbook

**Classification:** Standard Operating Procedures (SOP)  
**Target Audience:** Site Reliability Engineers (SRE), DevSecOps, Platform Engineers  

---

## 1. Production Deployment Runbook

### Prerequisites
- Container runtime with seccomp and cgroups v2 support (Docker 20.10+, Podman 4.0+, or Kubernetes 1.25+).
- Ingress reverse proxy (Nginx, Envoy, or Cloud Load Balancer) handling TLS termination (TLS 1.3 only).
- Secret management facility (HashiCorp Vault, AWS Secrets Manager, or Kubernetes Secrets).

### Deployment Procedure
1. **Pull and Verify Digest:**
   ```bash
   docker pull fortress/security-gateway:latest
   ```
2. **Launch with Hardened Security Opts:**
   ```bash
   docker run -d \
     --name fortress-gateway-prod \
     --user 10001:10001 \
     --read-only \
     --cap-drop ALL \
     --security-opt no-new-privileges:true \
     --security-opt seccomp=./deploy/seccomp-profile.json \
     --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
     --cpus 1.0 \
     --memory 512m \
     -p 127.0.0.1:3000:3000 \
     -e NODE_ENV=production \
     -e FORTRESS_HMAC_SECRET="$(cat /run/secrets/hmac_secret)" \
     fortress/security-gateway:latest
   ```

---

## 2. Health Monitoring & Observability

### Endpoint: `/api/health`
- **Method:** `GET`
- **Response Format:** JSON
- **Sensitivity:** Low (zero disclosure of environment variables, software versions, or database connection strings).
```json
{
  "status": "HEALTHY",
  "timestamp": "2026-10-23T06:55:00.000Z",
  "uptimeSeconds": 1420
}
```

---

## 3. Cryptographic Key Rotation Procedure

Master HMAC secrets and envelope encryption keys must be rotated every 90 days or immediately following suspected compromise:

1. **Generate High-Entropy Secret (Minimum 256 bits):**
   ```bash
   openssl rand -base64 32
   ```
2. **Execute Dual-Key Transitional Phase:**
   - Register the new key ID (`k-2027-q1`) into the SecretManager keyring.
   - Set the new key as active for encryption.
   - Retain the previous key (`k-2026-q4`) in the keyring as decrypt-only for 7 days to process in-flight tokens and envelopes.
3. **Decommission Previous Key:**
   - Verify that all active tokens signed under `k-2026-q4` have expired (maximum TTL: 24h).
   - Purge `k-2026-q4` from active keyring memory.

---

## 4. Backup & Disaster Recovery

- **Stateless Gateway Design:** Project Fortress runs as a stateless security enforcement gateway. Configuration is declarative and version-controlled.
- **Recovery Time Objective (RTO):** < 30 seconds (container restart with identical configuration).
- **Recovery Point Objective (RPO):** Zero data loss (telemetry is asynchronously dispatched to secure append-only audit sinks).
