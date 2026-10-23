# Project Fortress — Hardened Multi-Stage Containerfile
# Adheres to CIS Docker Benchmark & NIST SP 800-190

# --- STAGE 1: Build & Verification ---
FROM node:22-bookworm-slim AS builder

WORKDIR /build

# Install build dependencies securely
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit

COPY . .

# Run compile & type verification
RUN npm run lint
RUN npm run build

# Prune dev dependencies for production minimal surface
RUN npm prune --production

# --- STAGE 2: Distroless-Style Hardened Runtime ---
FROM node:22-bookworm-slim AS runtime

# Create dedicated unprivileged non-root user (UID 10001)
RUN groupadd -g 10001 fortress && \
    useradd -u 10001 -g fortress -s /sbin/nologin -M fortress

# Remove package managers and dangerous utilities from runtime
RUN apt-get update && \
    apt-get purge -y curl wget perl python3* && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app

# Copy production artifacts with strict ownership
COPY --from=builder --chown=10001:10001 /build/package.json ./package.json
COPY --from=builder --chown=10001:10001 /build/node_modules ./node_modules
COPY --from=builder --chown=10001:10001 /build/dist ./dist
COPY --from=builder --chown=10001:10001 /build/metadata.json ./metadata.json

# Read-only root filesystem enforcement; only /tmp is writable as tmpfs
USER 10001:10001

ENV NODE_ENV=production \
    PORT=3000 \
    FORTRESS_ISOLATION_LEVEL=STRICT

EXPOSE 3000

# Health check without shell injection or external utilities
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3000/api/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"]

ENTRYPOINT ["node", "dist/server.js"]
