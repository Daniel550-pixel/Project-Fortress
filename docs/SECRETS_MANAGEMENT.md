# Project Fortress — Secrets Management Integration Strategy

**Document Version:** 1.0.0  
**Classification:** Infrastructure Security Architecture & Implementation Guide  
**Status:** Approved  
**Target Runtime:** Node.js v22 LTS / TypeScript (Strict ESM) / Containerized Linux  

---

## 1. Executive Summary & Objective

In modern cybersecurity architectures, credential leakage, static secret exposure, and hardcoded encryption keys represent leading initial access vectors. This document investigates enterprise secrets management tools compatible with the **Project Fortress** TypeScript/Node.js stack, evaluates their suitability for sovereign and air-gapped deployments, and defines a production-ready integration strategy with concrete code implementations, key rotation workflows, and operational runbooks.

---

## 2. Comparative Evaluation of Secrets Management Tools

| Solution | Deployment Model | Authentication Mechanism | Dynamic Secrets & Rotation | Sovereign / Air-Gap Readiness | TypeScript / Node.js SDK |
|---|---|---|---|---|---|
| **HashiCorp Vault** | Self-hosted on-prem, multi-cloud, or HCP Vault | Kubernetes ServiceAccount, AppRole, TLS Certificates | Native dynamic secret engines; automated TTL & lease management | **Highest** (Full data sovereignty, local HSM integration) | `@hashicorp/vault-client` or native HTTP API |
| **AWS Secrets Manager & KMS** | Cloud-managed (AWS only) | IAM Roles / IRSA (IAM Roles for Service Accounts) | Built-in Lambda-based rotation for databases and API keys | Moderate (Tied to AWS global control plane) | `@aws-sdk/client-secrets-manager` |
| **Google Cloud Secret Manager & KMS** | Cloud-managed (GCP only) | Workload Identity Federation / Service Accounts | Versioned secret lifecycles; Cloud Functions rotation triggers | Moderate (Tied to Google Cloud control plane) | `@google-cloud/secret-manager` |
| **External Secrets Operator (ESO) + K8s** | Kubernetes Operator syncing from external Vault/KMS | In-cluster ServiceAccount with OIDC token projection | Reconciles external secrets into in-memory K8s Secrets | **High** (Kubernetes native, cloud-agnostic) | Native Node.js file mount (`/run/secrets/*`) |
| **Fortress Native Envelope SecretManager** | In-process zero-dependency crypto (`src/security/secrets.ts`) | Master Key seed injection via memory | Dual-key envelope encryption (AES-256-GCM); memory zeroization | **Highest** (Zero network latency, no external SaaS dependencies) | Built-in (`node:crypto` / WebCrypto) |

---

## 3. Recommended Production Architecture

To satisfy sovereign compliance, high throughput, and zero external dependency risk, Project Fortress employs a **Two-Tier Secret Isolation Architecture**:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   TIER 1: ENTERPRISE SECRET VAULT                      │
│            (HashiCorp Vault / Cloud KMS / Azure Key Vault)             │
│   - Master Encryption Keys (KEK: Key Encryption Keys)                  │
│   - Database Credentials, Third-Party API Keys                         │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (OIDC / Kubernetes ServiceAccount Auth)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│             TIER 2: EXTERNAL SECRETS OPERATOR (ESO)                    │
│   - Fetches secrets at pod startup or upon scheduled lease renewal     │
│   - Mounts secrets directly to in-memory tmpfs (/run/secrets/*)        │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (File read from memory-backed tmpfs)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 PROJECT FORTRESS RUNTIME GATEWAY                       │
│   - Ingests secrets via `validateAndLoadConfig()`                     │
│   - Uses AES-256-GCM Envelope Encryption (`src/security/secrets.ts`)   │
│   - Deterministic Redaction in Logs (`src/security/logger.ts`)         │
│   - Memory Zeroization (`SecretManager.zeroize()`)                     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Prerequisites for Deployment

1. **Kubernetes Environment:**
   - Kubernetes v1.25+ with Projected ServiceAccount Tokens enabled.
   - External Secrets Operator installed in cluster (`external-secrets` namespace).
2. **Network Egress Constraints:**
   - If utilizing HashiCorp Vault: Secure mutual TLS (mTLS) connectivity between worker pods and Vault listener over port `8200`.
   - Outbound DNS resolution restricted strictly to the Vault cluster endpoint.
3. **IAM / Vault Policy:**
   - Least-privilege policy allowing `read` access strictly to the path `secret/data/fortress/*`.
   - Write/delete operations restricted to the automated rotation pipeline.

---

## 5. Kubernetes & External Secrets Operator Integration

### 5.1 External Secret Store Definition
Create `deploy/secret-store.yaml`:
```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: fortress-vault-store
  namespace: fortress-system
spec:
  provider:
    vault:
      server: "https://vault.internal.gov.ae:8200"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "fortress-gateway-role"
          serviceAccountRef:
            name: fortress-service-account
```

### 5.2 ExternalSecret Mapping
Create `deploy/external-secret.yaml`:
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: fortress-secrets-sync
  namespace: fortress-system
spec:
  refreshInterval: "1h"
  secretStoreRef:
    name: fortress-vault-store
    kind: SecretStore
  target:
    name: fortress-live-secrets
    creationPolicy: Owner
  data:
    - secretKey: FORTRESS_HMAC_SECRET
      remoteRef:
        key: fortress/production
        property: hmac_master_key
    - secretKey: MASTER_ENVELOPE_KEY
      remoteRef:
        key: fortress/production
        property: envelope_encryption_seed
```

### 5.3 Pod Manifest with Memory-Backed Secret Mount
Update Kubernetes deployment to mount secrets from `tmpfs`:
```yaml
spec:
  containers:
    - name: fortress
      image: fortress/security-gateway:latest
      volumeMounts:
        - name: secret-volume
          mountPath: /run/secrets
          readOnly: true
  volumes:
    - name: secret-volume
      secret:
        secretName: fortress-live-secrets
        defaultMode: 0400
```

---

## 6. TypeScript Application Secret Ingestion Pattern

The following module (`src/security/vaultProvider.ts`) securely reads secrets from either `/run/secrets/` (container mount) or fallback environment variables, validating entropy and key length:

```typescript
import fs from 'node:fs';
import path from 'node:path';
import { ValidationError } from './errors.ts';

const SECRETS_DIR = '/run/secrets';

/**
 * Safely resolves a secret value from file mount or environment.
 */
export function resolveSecret(secretName: string, fallbackEnvVar?: string): string {
  const filePath = path.join(SECRETS_DIR, secretName);

  // 1. Prefer in-memory file mount from External Secrets Operator
  if (fs.existsSync(filePath)) {
    try {
      const val = fs.readFileSync(filePath, 'utf-8').trim();
      if (val.length >= 32) {
        return val;
      }
    } catch {
      // Fall through to environment variable
    }
  }

  // 2. Fallback to validated environment variable
  const envVal = fallbackEnvVar ? process.env[fallbackEnvVar] : process.env[secretName];
  if (envVal && envVal.trim().length >= 32) {
    return envVal.trim();
  }

  throw new ValidationError(
    `Secret '${secretName}' could not be resolved from ${filePath} or environment, or does not meet minimum 32-character requirement.`
  );
}
```

---

## 7. Envelope Encryption & Key Rotation Runbook

When encrypting sensitive application data at rest (e.g. audit records, user profiles), Project Fortress utilizes **Envelope Encryption** via `src/security/secrets.ts`.

### 7.1 Encryption Flow
1. A 256-bit Key Encryption Key (KEK) is derived from the master secret.
2. A unique 96-bit Initialization Vector (IV) is generated cryptographically using `crypto.getRandomValues()`.
3. Plaintext is encrypted under AES-256-GCM, producing ciphertext and an authenticated 128-bit authentication tag.
4. The output is stored as an immutable `EncryptedEnvelope` containing `version`, `keyId`, `iv`, `ciphertext`, and `tag`.

### 7.2 Zero-Downtime Key Rotation Procedure
1. **Step 1 — Register New Key:**
   ```typescript
   import { defaultSecretManager } from './security/secrets.ts';
   defaultSecretManager.rotateKey('k-2027-q1', newCryptographicMasterSeed);
   ```
2. **Step 2 — Dual-Key Operation:**
   The `SecretManager` automatically retains previous keys (`k-2026-q4`) in its keyring, allowing existing envelopes to decrypt seamlessly while newly created records are encrypted under `k-2027-q1`.
3. **Step 3 — Re-encryption Migration:**
   A background worker reads existing envelopes and re-encrypts them under the active key:
   ```typescript
   const decrypted = await defaultSecretManager.decryptSecret(oldEnvelope);
   const updatedEnvelope = await defaultSecretManager.encryptSecret(decrypted);
   await saveEnvelope(recordId, updatedEnvelope);
   ```
4. **Step 4 — Decommissioning:**
   Once all legacy envelopes have been re-encrypted, the old key ID is purged from the keyring.

---

## 8. Memory Hygiene & Anti-Patterns Checklist

| Anti-Pattern | Operational Risk | Fortress Mitigation |
|---|---|---|
| **Hardcoding secrets in code** | Permanent exposure in Git history | Automated secret scanning pre-commit + CI failure gate. |
| **Embedding secrets in Dockerfile `ENV`** | Secrets readable via `docker inspect` and image layers | Multi-stage build with secrets mounted at runtime via `/run/secrets/`. |
| **Passing secrets in CLI flags** | Exposed in process list (`ps aux`) and bash history | Secrets passed strictly via file mounts or private environment variables. |
| **Printing objects with secrets in logs** | Credential leakage in cloud logging / SIEM | Deterministic redactor in `src/security/logger.ts` scrubbing keys and tokens. |
| **Leaving plaintext keys in memory** | Core dump or memory snapshot exfiltration | `SecretManager.zeroize(buffer)` systematically wipes buffers after cryptographic use. |
| **Passing secrets in HTTP query parameters** | Logged in access logs and browser history | Credentials restricted strictly to `Authorization: Bearer <token>` headers. |
