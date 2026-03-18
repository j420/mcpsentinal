import type { RuleFixtureSet } from "../types.js";

const base = {
  server: { id: "test", name: "test-server", description: null, github_url: null },
  tools: [],
  dependencies: [],
  connection_metadata: null,
};

function srcCtx(source_code: string) {
  return { ...base, source_code };
}

// ── P1: Docker Socket Mount in Container ────────────────────────────────────
export const P1: RuleFixtureSet = {
  rule_id: "P1",
  rule_name: "Docker Socket Mount in Container",
  fixtures: [
    {
      description: "docker-compose.yml mounts Docker socket into MCP server container",
      context: srcCtx(`version: '3.8'
services:
  mcp-server:
    image: mcp-server:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    ports:
      - "3000:3000"`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CIS Docker Benchmark v1.7.0 Section 5.4 — never mount container runtime sockets",
    },
    {
      description: "Kubernetes hostPath mounts containerd socket",
      context: srcCtx(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: mcp-server
      volumeMounts:
        - name: containerd-sock
          mountPath: /run/containerd/containerd.sock
  volumes:
    - name: containerd-sock
      hostPath:
        path: /run/containerd/containerd.sock`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CVE-2025-9074 — container escape via runtime socket access",
    },
    {
      description: "docker run command with -v mounting docker.sock",
      context: srcCtx(`#!/bin/bash
docker run -d \\
  -v /var/run/docker.sock:/var/run/docker.sock \\
  -p 3000:3000 \\
  mcp-server:latest`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "docker-compose mounts Podman socket",
      context: srcCtx(`services:
  mcp-server:
    image: mcp-server:latest
    volumes:
      - /run/podman/podman.sock:/run/podman/podman.sock`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: docker-compose mounts only data volume, no socket",
      context: srcCtx(`version: '3.8'
services:
  mcp-server:
    image: mcp-server:latest
    volumes:
      - ./data:/app/data
    ports:
      - "3000:3000"`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: test fixture references docker.sock in a comment",
      context: srcCtx(`// test: verify we never mount docker.sock
// see: /var/run/docker.sock
describe('container security', () => {
  it('should not mount docker.sock', () => {
    expect(config.volumes).not.toContain('docker.sock');
  });
});`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── P2: Dangerous Container Capabilities ────────────────────────────────────
export const P2: RuleFixtureSet = {
  rule_id: "P2",
  rule_name: "Dangerous Container Capabilities",
  fixtures: [
    {
      description: "docker-compose sets privileged: true on container",
      context: srcCtx(`version: '3.8'
services:
  mcp-server:
    image: mcp-server:latest
    privileged: true
    ports:
      - "3000:3000"`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CVE-2025-23266 (NVIDIAScape) + CIS Docker Benchmark 5.3 — no privileged containers",
    },
    {
      description: "Kubernetes sets hostPID: true and adds SYS_MODULE capability",
      context: srcCtx(`apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      hostPID: true
      containers:
        - name: mcp-server
          securityContext:
            capabilities:
              add:
                - SYS_MODULE`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "docker run with --privileged flag",
      context: srcCtx(`docker run --privileged -d mcp-server:latest`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Container with allowPrivilegeEscalation: true",
      context: srcCtx(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: mcp-server
      securityContext:
        allowPrivilegeEscalation: true`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: container drops ALL capabilities and blocks privilege escalation",
      context: srcCtx(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: mcp-server
      securityContext:
        capabilities:
          drop:
            - ALL
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: test Dockerfile uses privileged mode for integration testing",
      context: srcCtx(`# test/docker-compose.test.yml
# This test environment uses privileged for CI integration testing
services:
  test-runner:
    image: test-runner:latest`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── P3: Cloud Metadata Service Access ───────────────────────────────────────
export const P3: RuleFixtureSet = {
  rule_id: "P3",
  rule_name: "Cloud Metadata Service Access",
  fixtures: [
    {
      description: "Direct fetch to AWS metadata service for IAM credentials",
      context: srcCtx(`async function getAwsCreds() {
  const resp = await fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name');
  return resp.json();
}`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CVE-2025-53767 (Azure OpenAI SSRF, CVSS 10.0) — metadata service exploitation",
    },
    {
      description: "DNS rebinding bypass via nip.io to reach metadata endpoint",
      context: srcCtx(`const metadataUrl = 'http://169.254.169.254.nip.io/latest/meta-data/';
const response = await axios.get(metadataUrl);`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CVE-2026-27730 — esm.sh SSRF via nip.io bypass",
    },
    {
      description: "GCP metadata access with Metadata-Flavor header",
      context: srcCtx(`const response = await fetch('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', {
  headers: { 'Metadata-Flavor': 'Google' }
});`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Hex-encoded metadata IP to evade simple string matching",
      context: srcCtx(`// bypass metadata firewall with hex IP
const url = 'http://0xa9fea9fe/latest/meta-data/iam/security-credentials/';
http.get(url, callback);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: code uses IMDSv2 with proper token TTL header",
      context: srcCtx(`// IMDSv2 secure access
const tokenResp = await fetch('http://169.254.169.254/latest/api/token', {
  method: 'PUT',
  headers: { 'X-aws-ec2-metadata-token-ttl-seconds': '21600' }
});`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: test fixture mocking metadata service responses",
      context: srcCtx(`// test/metadata.spec.ts
// mock 169.254.169.254 for unit testing
describe('metadata client', () => {
  it('handles timeout', () => {
    nock('http://169.254.169.254').get('/latest/meta-data/').replyWithError('timeout');
  });
});`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── P4: TLS Certificate Validation Bypass ───────────────────────────────────
export const P4: RuleFixtureSet = {
  rule_id: "P4",
  rule_name: "TLS Certificate Validation Bypass",
  fixtures: [
    {
      description: "Dockerfile sets NODE_TLS_REJECT_UNAUTHORIZED=0 globally",
      context: srcCtx(`FROM node:20-slim
WORKDIR /app
COPY . .
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
RUN npm install
CMD ["node", "server.js"]`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "Claude Code MCP issue #9869 — TLS bypass is unacceptable security risk for MCP",
    },
    {
      description: "Python requests library with verify=False",
      context: srcCtx(`import requests

def call_external_api(url, data):
    response = requests.post(url, json=data, verify=False)
    return response.json()`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Node.js https agent with rejectUnauthorized: false",
      context: srcCtx(`const https = require('https');
const agent = new https.Agent({
  rejectUnauthorized: false
});
const response = await fetch(url, { agent });`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Go TLS config with InsecureSkipVerify: true",
      context: srcCtx(`tr := &http.Transport{
  TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
client := &http.Client{Transport: tr}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: proper TLS with NODE_EXTRA_CA_CERTS for custom CA",
      context: srcCtx(`FROM node:20-slim
WORKDIR /app
COPY certs/custom-ca.pem /etc/ssl/certs/
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/custom-ca.pem
CMD ["node", "server.js"]`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: test file disables TLS for localhost tests only",
      context: srcCtx(`// test/integration.spec.ts
// localhost test server uses self-signed certs
const agent = new https.Agent({
  ca: fs.readFileSync('test/certs/test-ca.pem')
});`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── P5: Secrets Exposed in Container Build Layers ───────────────────────────
export const P5: RuleFixtureSet = {
  rule_id: "P5",
  rule_name: "Secrets Exposed in Container Build Layers",
  fixtures: [
    {
      description: "Dockerfile ARG with DB_PASSWORD persisted in image layer",
      context: srcCtx(`FROM node:20-slim
ARG DB_PASSWORD=supersecretpassword123
ENV DATABASE_URL=postgres://user:$DB_PASSWORD@db:5432/app
RUN npm install
CMD ["node", "server.js"]`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CIS Docker Benchmark v1.7.0 Section 4.10 — do not store secrets in Dockerfiles",
    },
    {
      description: "COPY .env file into Docker image layer",
      context: srcCtx(`FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY .env /app/.env
COPY . .
CMD ["python", "main.py"]`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Kubernetes ConfigMap used for secrets instead of Secret object",
      context: srcCtx(`apiVersion: v1
kind: ConfigMap
metadata:
  name: mcp-config
data:
  database_password: hunter2
  api_key: sk-live-abc123xyz456`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "docker run with inline secret value in -e flag",
      context: srcCtx(`docker run -d \\
  -e API_KEY=sk_live_1234567890abcdef \\
  -p 3000:3000 \\
  mcp-server:latest`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: Dockerfile uses BuildKit --mount=type=secret",
      context: srcCtx(`# syntax=docker/dockerfile:1
FROM node:20-slim
WORKDIR /app
COPY package*.json ./
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm install
COPY . .
CMD ["node", "server.js"]`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: docker-compose uses environment variable references",
      context: srcCtx(`services:
  mcp-server:
    image: mcp-server:latest
    environment:
      - DATABASE_URL=\${DATABASE_URL}
      - API_KEY=\${API_KEY}`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── P6: LD_PRELOAD and Shared Library Hijacking ─────────────────────────────
export const P6: RuleFixtureSet = {
  rule_id: "P6",
  rule_name: "LD_PRELOAD and Shared Library Hijacking",
  fixtures: [
    {
      description: "Dockerfile sets ENV LD_PRELOAD to load custom shared library",
      context: srcCtx(`FROM ubuntu:22.04
WORKDIR /app
COPY libhook.so /app/libhook.so
ENV LD_PRELOAD=/app/libhook.so
CMD ["./mcp-server"]`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CVE-2025-23266 (NVIDIAScape, CVSS 9.0) — LD_PRELOAD container escape",
    },
    {
      description: "Code reads /proc/self/mem for process memory injection",
      context: srcCtx(`const fs = require('fs');
const fd = fs.openSync('/proc/self/mem', 'r+');
const buffer = Buffer.alloc(1024);
fs.readSync(fd, buffer, 0, 1024, 0x400000);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "LD_LIBRARY_PATH set to writable tmp directory",
      context: srcCtx(`export LD_LIBRARY_PATH=/tmp/libs:/app/libs
./mcp-server --port 3000`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python ctypes loading user-controlled library path",
      context: srcCtx(`import ctypes
def load_plugin(user_input):
    lib = ctypes.cdll.LoadLibrary(user_input)
    return lib.process()`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: code reads /proc/self/status for memory monitoring",
      context: srcCtx(`const memInfo = fs.readFileSync('/proc/self/status', 'utf-8');
const vmRSS = memInfo.match(/VmRSS:\\s+(\\d+)/);
logger.info({ rss_kb: vmRSS?.[1] }, 'memory usage');`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: test fixture references LD_PRELOAD in documentation comment",
      context: srcCtx(`// test/security.spec.ts
// This test verifies LD_PRELOAD is not set in production containers
describe('container hardening', () => {
  it('should not use LD_PRELOAD', () => {
    expect(env.LD_PRELOAD).toBeUndefined();
  });
});`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── P7: Sensitive Host Filesystem Mount ─────────────────────────────────────
export const P7: RuleFixtureSet = {
  rule_id: "P7",
  rule_name: "Sensitive Host Filesystem Mount",
  fixtures: [
    {
      description: "docker-compose mounts host root filesystem into container",
      context: srcCtx(`version: '3.8'
services:
  mcp-server:
    image: mcp-server:latest
    volumes:
      - /:/host:rw
    ports:
      - "3000:3000"`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CVE-2025-53109/53110 — Anthropic filesystem MCP server root boundary bypass",
    },
    {
      description: "docker-compose mounts /etc into container",
      context: srcCtx(`services:
  mcp-server:
    image: mcp-server:latest
    volumes:
      - /etc:/host-etc
    ports:
      - "3000:3000"`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Kubernetes hostPath mounts /root/.ssh for SSH key access",
      context: srcCtx(`apiVersion: v1
kind: Pod
spec:
  volumes:
    - name: ssh-keys
      hostPath:
        path: /root/.ssh
  containers:
    - name: mcp-server
      volumeMounts:
        - name: ssh-keys
          mountPath: /root/.ssh`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "docker run mounts /proc with read-write access",
      context: srcCtx(`docker run -d \\
  --mount type=bind,source=/proc,target=/host-proc,readwrite \\
  mcp-server:latest`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: docker-compose mounts only application data directory",
      context: srcCtx(`version: '3.8'
services:
  mcp-server:
    image: mcp-server:latest
    volumes:
      - ./app-data:/app/data
      - mcp-logs:/app/logs
    ports:
      - "3000:3000"`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: Kubernetes hostPath with readOnly: true",
      context: srcCtx(`apiVersion: v1
kind: Pod
spec:
  volumes:
    - name: config
      hostPath:
        path: /opt/mcp-config
  containers:
    - name: mcp-server
      volumeMounts:
        - name: config
          mountPath: /config
          readOnly: true`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── P8: Insecure Cryptographic Mode or Static IV/Nonce ──────────────────────
export const P8: RuleFixtureSet = {
  rule_id: "P8",
  rule_name: "Insecure Cryptographic Mode or Static IV/Nonce",
  fixtures: [
    {
      description: "AES-ECB mode used for encrypting MCP server tokens",
      context: srcCtx(`const crypto = require('crypto');
const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
const encrypted = cipher.update(token, 'utf8', 'hex') + cipher.final('hex');`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "NIST SP 800-38A — ECB mode not recommended for multi-block messages",
    },
    {
      description: "Static hardcoded IV used with AES encryption",
      context: srcCtx(`const iv = Buffer.from('0000000000000000', 'hex');
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
const encrypted = cipher.update(data, 'utf8', 'hex');`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python AES.MODE_ECB with PyCryptodome",
      context: srcCtx(`from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
encrypted = cipher.encrypt(pad(plaintext, AES.block_size))`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Math.random used for IV generation instead of CSPRNG",
      context: srcCtx(`function generateIV() {
  const iv = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) {
    iv[i] = Math.floor(Math.random() * 256);
  }
  return iv;
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: AES-256-GCM with crypto.randomBytes for IV",
      context: srcCtx(`const crypto = require('crypto');
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const encrypted = cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
const tag = cipher.getAuthTag();`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: test fixture uses ECB for testing encryption error paths",
      context: srcCtx(`// test/crypto.spec.ts
describe('encryption', () => {
  it('rejects ECB mode', () => {
    expect(() => encrypt(data, { mode: 'ecb' })).toThrow('ECB mode not allowed');
  });
});`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── P9: Missing Container Resource Limits ───────────────────────────────────
export const P9: RuleFixtureSet = {
  rule_id: "P9",
  rule_name: "Missing Container Resource Limits",
  fixtures: [
    {
      description: "Fork bomb pattern in source code with no PID limit protection",
      context: srcCtx(`const { fork } = require('child_process');
while (true) {
  fork(__filename);
}`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CVE-2025-26449 — permanent DoS via resource exhaustion when limits not set",
    },
    {
      description: "PID limit explicitly set to unlimited (no fork bomb protection)",
      context: srcCtx(`docker run --pids-limit=-1 -d mcp-server:latest`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "ulimit nproc set to unlimited",
      context: srcCtx(`docker run --ulimit nproc=unlimited -d mcp-server:latest`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: docker-compose with proper resource limits",
      context: srcCtx(`services:
  mcp-server:
    image: mcp-server:latest
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
    mem_limit: 512m
    cpus: 0.5`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: Kubernetes pod with resource limits defined",
      context: srcCtx(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: mcp-server
      image: mcp-server:latest
      resources:
        limits:
          memory: 256Mi
          cpu: 500m
        requests:
          memory: 128Mi
          cpu: 250m`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── P10: Host Network Mode and Missing Egress Controls ──────────────────────
export const P10: RuleFixtureSet = {
  rule_id: "P10",
  rule_name: "Host Network Mode and Missing Egress Controls",
  fixtures: [
    {
      description: "docker-compose sets network_mode: host on MCP server",
      context: srcCtx(`version: '3.8'
services:
  mcp-server:
    image: mcp-server:latest
    network_mode: host`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CIS Docker Benchmark v1.7.0 Section 5.9 — do not use host network mode",
    },
    {
      description: "Kubernetes pod spec sets hostNetwork: true",
      context: srcCtx(`apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
    - name: mcp-server
      image: mcp-server:latest
      ports:
        - containerPort: 3000`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "docker run with --network=host flag",
      context: srcCtx(`docker run --network=host -d mcp-server:latest`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "MCP server code performs internal network scanning with nmap",
      context: srcCtx(`const { execSync } = require('child_process');
function discoverServices() {
  const result = execSync('nmap -sn 192.168.1.0/24');
  return parseNmapOutput(result.toString());
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: docker-compose uses default bridge networking with port mapping",
      context: srcCtx(`version: '3.8'
services:
  mcp-server:
    image: mcp-server:latest
    network_mode: bridge
    ports:
      - "3000:3000"`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: Kubernetes deployment with NetworkPolicy restricting egress",
      context: srcCtx(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mcp-server-egress
spec:
  podSelector:
    matchLabels:
      app: mcp-server
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

export const ALL_P_FIXTURES: RuleFixtureSet[] = [
  P1, P2, P3, P4, P5, P6, P7, P8, P9, P10,
];
