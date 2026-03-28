# Sprint 3: Container & Runtime — Migrate Rules from YAML Regex to TypeScript

## Mission

You are the **P8 Detection Rule Engineer**. Migrate the **Container & Runtime** risk domain rules from YAML regex to TypeScript. These rules detect container misconfigurations and runtime security issues in MCP server deployments.

**Shared context (AnalysisContext, TypedRule interface, existing toolkits, registration pattern):** See `docs/migration-prompts/sprint-1-human-oversight.md`.

## Architecture Note

These rules analyze Dockerfiles, docker-compose YAML, Kubernetes manifests, and application source code. When `source_files` map is available, route each file to the appropriate parser by file path. When only `source_code` string is available, detect embedded Dockerfile/YAML sections by content markers (`FROM`, `services:`, `apiVersion:`).

## Rules to Migrate

### Rule P1 — Docker Socket Mount (PURE REGEX → TypeScript)

**YAML:** `rules/P1-docker-socket-mount.yaml` | **Severity:** critical
**Intelligence:** CVE-2025-9074 (Docker Desktop container escape, CVSS 9.3)

**Analysis technique:** Parse volume mount declarations in Dockerfile/compose/k8s for container runtime socket paths:
- Docker: `/var/run/docker.sock`
- containerd: `/run/containerd/containerd.sock`
- CRI-O: `/var/run/crio/crio.sock`
- Podman: `/run/podman/podman.sock`

Check `volumes:`, `-v` flags, `VOLUME` directives, and k8s `hostPath` mounts.

**Confidence:** Socket path in volume mount → 0.95 | In hostPath → 0.90 | Regex fallback → 0.50

**Test cases (4 TP + 4 TN):**

```typescript
// TP1: docker-compose volume mount
const tp1 = `
services:
  mcp-server:
    image: my-mcp:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock`;

// TP2: Kubernetes hostPath mount
const tp2 = `
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: mcp-server
      volumeMounts:
        - name: docker-sock
          mountPath: /var/run/docker.sock
  volumes:
    - name: docker-sock
      hostPath:
        path: /var/run/docker.sock`;

// TP3: containerd socket mount
const tp3 = `
services:
  mcp-server:
    volumes:
      - /run/containerd/containerd.sock:/run/containerd/containerd.sock`;

// TP4: Dockerfile VOLUME directive
const tp4 = `
FROM node:20
VOLUME ["/var/run/docker.sock"]
COPY . /app
CMD ["node", "server.js"]`;

// TN1: Normal data volume (should NOT flag)
const tn1 = `
services:
  mcp-server:
    volumes:
      - ./data:/app/data
      - mcp-logs:/var/log/mcp`;

// TN2: Comment mentioning docker.sock (should NOT flag)
const tn2 = `
# WARNING: Never mount /var/run/docker.sock in production
# See CIS Docker Benchmark 5.4
services:
  mcp-server:
    volumes:
      - ./config:/app/config`;

// TN3: Test fixture (should NOT flag)
const tn3 = `
// test/docker-integration.test.ts
const testConfig = {
  volumes: ['/var/run/docker.sock:/var/run/docker.sock']
};`;

// TN4: Docker socket proxy (safe alternative, should NOT flag)
const tn4 = `
services:
  docker-proxy:
    image: tecnativa/docker-socket-proxy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  mcp-server:
    environment:
      - DOCKER_HOST=tcp://docker-proxy:2375`;
```

---

### Rule P2 — Dangerous Container Capabilities (PURE REGEX → TypeScript)

**YAML:** `rules/P2-dangerous-capabilities.yaml` | **Severity:** critical
**Intelligence:** CVE-2025-23266 (NVIDIAScape, CVSS 9.0), CVE-2025-31133 (runc trilogy)

**Analysis technique:** Parse securityContext/cap_add/privileged in compose/k8s:
- `privileged: true`, `--privileged`
- Dangerous capabilities: `SYS_ADMIN`, `SYS_RAWIO`, `SYS_MODULE`, `NET_ADMIN`, `SYS_PTRACE`, `DAC_OVERRIDE`
- `hostPID: true`, `hostIPC: true`, `allowPrivilegeEscalation: true`

**Confidence:** `privileged: true` → 0.95 | Dangerous cap_add → 0.90 | hostPID/IPC → 0.85

```typescript
// TP1: privileged container
const tp1 = `
services:
  mcp-server:
    privileged: true
    image: my-mcp:latest`;

// TP2: Kubernetes dangerous capabilities
const tp2 = `
spec:
  containers:
    - name: mcp-server
      securityContext:
        capabilities:
          add: ["SYS_ADMIN", "NET_RAW"]
        allowPrivilegeEscalation: true`;

// TP3: Host PID namespace
const tp3 = `
apiVersion: v1
kind: Pod
spec:
  hostPID: true
  containers:
    - name: mcp-server`;

// TP4: Docker run with --privileged
const tp4 = `
#!/bin/bash
docker run --privileged -d my-mcp-server:latest`;

// TN1: Minimal capabilities with drop ALL (should NOT flag)
const tn1 = `
spec:
  containers:
    - name: mcp-server
      securityContext:
        capabilities:
          drop: ["ALL"]
        allowPrivilegeEscalation: false
        runAsNonRoot: true`;

// TN2: Test environment using privileged (should NOT flag)
const tn2 = `
# test/docker-compose.test.yml
services:
  test-db:
    image: postgres:15
    privileged: true  # needed for shared memory in tests`;

// TN3: Read-only security context (should NOT flag)
const tn3 = `
spec:
  containers:
    - name: mcp-server
      securityContext:
        readOnlyRootFilesystem: true
        runAsUser: 1000`;

// TN4: NET_BIND_SERVICE only (safe, should NOT flag)
const tn4 = `
spec:
  containers:
    - name: mcp-server
      securityContext:
        capabilities:
          drop: ["ALL"]
          add: ["NET_BIND_SERVICE"]`;
```

---

### Rule P4 — TLS Certificate Validation Bypass (PURE REGEX → TypeScript)

**YAML:** `rules/P4-tls-certificate-validation-bypass.yaml` | **Severity:** critical
**Intelligence:** Claude Code MCP issue #9869, OWASP A07:2021

**Analysis technique:** Detect TLS bypass across languages:
- Node.js: `NODE_TLS_REJECT_UNAUTHORIZED=0`, `rejectUnauthorized: false`
- Python: `verify=False`, `ssl._create_unverified_context`
- Go: `InsecureSkipVerify: true`
- Java: `TrustAllCerts`, `AllowAllHostnameVerifier`
- CLI: `curl -k`, `wget --no-check-certificate`
- Dockerfile: `ENV NODE_TLS_REJECT_UNAUTHORIZED 0`

**Confidence:** Global TLS disable (env var) → 0.95 | Per-request disable → 0.85 | CLI flag → 0.75

```typescript
// TP1: Node.js global TLS bypass
const tp1 = `
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const client = new MCPClient(serverUrl);`;

// TP2: Python requests verify=False
const tp2 = `
import requests
def call_mcp_server(url, payload):
    return requests.post(url, json=payload, verify=False)`;

// TP3: Dockerfile ENV disabling TLS
const tp3 = `
FROM node:20-alpine
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
COPY . /app
CMD ["node", "server.js"]`;

// TP4: Node.js per-request TLS bypass
const tp4 = `
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: false });
fetch(mcpServerUrl, { agent });`;

// TN1: Localhost/dev exception (should NOT flag)
const tn1 = `
if (process.env.NODE_ENV === 'development' && url.includes('localhost')) {
  agent = new https.Agent({ rejectUnauthorized: false });
}`;

// TN2: Custom CA bundle (safe, should NOT flag)
const tn2 = `
process.env.NODE_EXTRA_CA_CERTS = '/etc/ssl/custom-ca.pem';
const client = new MCPClient(serverUrl);`;

// TN3: Test file (should NOT flag)
const tn3 = `
// test/integration.test.ts
const agent = new https.Agent({ rejectUnauthorized: false });
const res = await fetch('https://localhost:3443/test', { agent });`;

// TN4: Comment explaining the risk (should NOT flag)
const tn4 = `
// NEVER set rejectUnauthorized: false in production
// See OWASP A07:2021 Cryptographic Failures
const agent = new https.Agent({ ca: customCA });`;
```

---

### Rule P5 — Secrets in Container Build Layers (PURE REGEX → TypeScript)

**YAML:** `rules/P5-secrets-in-build-layers.yaml` | **Severity:** critical
**Intelligence:** CIS Docker Benchmark v1.7.0 §4.10

**Analysis technique:** Parse Dockerfile instructions for credential exposure:
- `ARG` with credential-named variables (PASSWORD, TOKEN, API_KEY, SECRET, etc.)
- `ENV` with inline secret values (high-entropy strings >16 chars)
- `COPY`/`ADD` of credential files (.env, .pem, .p12, credentials)
- Kubernetes ConfigMap with secret-looking keys (should be Secret object)

**Confidence:** ARG/ENV with credential name + inline value → 0.92 | COPY .env → 0.85 | ARG credential name only → 0.70

```typescript
// TP1: ARG with secret value
const tp1 = `
FROM node:20
ARG DB_PASSWORD=supersecretpassword123
ENV DATABASE_URL=postgres://user:\${DB_PASSWORD}@db:5432/mcp`;

// TP2: COPY .env file into image
const tp2 = `
FROM python:3.11
COPY .env /app/.env
COPY requirements.txt /app/
RUN pip install -r /app/requirements.txt`;

// TP3: ENV with inline API key
const tp3 = `
FROM node:20
ENV ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxxxxxxxxx
COPY . /app`;

// TP4: ConfigMap with password (should be Secret)
const tp4 = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: mcp-config
data:
  database_password: hunter2
  api_token: sk-1234567890abcdef`;

// TN1: BuildKit secrets (safe, should NOT flag)
const tn1 = `
FROM node:20
RUN --mount=type=secret,id=npm_token \\
  NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci`;

// TN2: Variable reference, not inline value (should NOT flag)
const tn2 = `
FROM node:20
ARG NODE_VERSION
ENV DATABASE_URL=\${DATABASE_URL}`;

// TN3: Placeholder values (should NOT flag)
const tn3 = `
FROM node:20
ARG API_KEY=your_api_key_here
ENV TOKEN=changeme`;

// TN4: Test Dockerfile (should NOT flag)
const tn4 = `
# test/Dockerfile.test
FROM node:20
ENV API_KEY=test-key-not-real
COPY . /app`;
```

---

### Rules P6, P7, P8, P10 — Remaining Container Rules

For these rules, follow the same pattern as P1-P5 above. Key detection per rule:

**P6 (LD_PRELOAD Hijacking):** Detect `LD_PRELOAD=`, `ENV LD_PRELOAD`, `LD_LIBRARY_PATH` pointing to temp dirs, `dlopen` with user input, `/proc/pid/mem` access. Exclude `/proc/self/status` (monitoring). CVE-2025-23266 reference.

**P7 (Host Filesystem Mount):** Detect volume mounts of `/`, `/etc`, `/root`, `/home`, `/proc`, `/sys`, `/dev`, `/boot`, `~/.ssh`, `~/.aws`. Exclude read-only mounts (`readOnly: true`, `:ro`). CVE-2025-53109/53110 reference.

**P8 (Crypto Weakness):** Detect ECB mode (`AES-ECB`, `MODE_ECB`), static/zero IVs (`iv = Buffer.from('0000...')`), `Math.random()` for crypto, custom crypto implementations, PBKDF2 without salt. Exclude GCM/CCM/Poly1305 (safe modes).

**P10 (Host Network Mode):** Detect `network_mode: host`, `hostNetwork: true`, mDNS/SSDP scanning, ARP scanning from containers. Exclude bridge networking with port mapping.

Each rule: create TypedRule implementation + 8 test cases (4 TP + 4 TN).

---

## Files to Create/Modify

| File | Action |
|------|--------|
| `packages/analyzer/src/rules/implementations/p1-docker-socket.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/p2-dangerous-capabilities.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/p4-tls-bypass.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/p5-secrets-in-layers.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/p6-ld-preload.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/p7-host-filesystem.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/p8-crypto-weakness.ts` | **Create** |
| `packages/analyzer/src/rules/implementations/p10-host-network.ts` | **Create** |
| `packages/analyzer/src/rules/index.ts` | **Modify** — add 8 imports |
| `packages/analyzer/__tests__/rules/p-container-runtime.test.ts` | **Create** — 64 test cases (8 per rule) |
| `rules/P1-docker-socket-mount.yaml` | **Modify** — `type: regex` → `type: typed` |
| `rules/P2-dangerous-capabilities.yaml` | **Modify** — same |
| `rules/P4-tls-certificate-validation-bypass.yaml` | **Modify** — same |
| `rules/P5-secrets-in-build-layers.yaml` | **Modify** — same |
| `rules/P6-ld-preload-library-hijacking.yaml` | **Modify** — same |
| `rules/P7-host-filesystem-mount.yaml` | **Modify** — same |
| `rules/P8-ecb-mode-static-iv.yaml` | **Modify** — same |
| `rules/P10-network-host-mode.yaml` | **Modify** — same |

## Verification

1. `pnpm typecheck` — all packages pass
2. `pnpm test --filter=@mcp-sentinel/analyzer` — all tests pass including 64 new container tests
3. `bash tools/scripts/validate-rules.sh` — all 177 rules validate
4. All 8 P-rule YAML files no longer contain `patterns` or `context` fields
