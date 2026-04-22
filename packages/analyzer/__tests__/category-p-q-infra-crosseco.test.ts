/**
 * Categories: Infrastructure Runtime (P1-P10) + Cross-Ecosystem Emergent (Q1-Q15) — 65 tests
 *
 * Implementations in:
 *   - infrastructure-detector.ts (P1-P7)
 *   - compliance-remaining-detector.ts (P8, P9, P10, Q10, Q12, Q14, Q15)
 *   - data-privacy-cross-ecosystem-detector.ts (Q1-Q3, Q5-Q9, Q11, Q13)
 *   - config-poisoning-detector.ts (Q4)
 */
import { describe, it, expect } from "vitest";
import type { AnalysisContext } from "../src/engine.js";
import { getTypedRule } from "../src/rules/base.js";
import "../src/rules/index.js";
import { findingFor, expectEvidenceChain, expectConfidenceRange } from "./test-helpers.js";

function ctx(overrides: Partial<AnalysisContext> = {}): AnalysisContext {
  return { server: { id: "t", name: "test", description: null, github_url: null }, tools: [], source_code: null, dependencies: [], connection_metadata: null, ...overrides };
}
function run(id: string, src: string) { return getTypedRule(id)!.analyze(ctx({ source_code: src })); }
function runCtx(id: string, c: AnalysisContext) { return getTypedRule(id)!.analyze(c); }

// ═══════════════════════════════════════════════════════════════════════════
// P — Infrastructure Runtime
// ═══════════════════════════════════════════════════════════════════════════

// ─── P1 — Docker Socket Mount ────────────────────────────────────────────

describe("P1 — Docker Socket Mount", () => {
  it("flags docker.sock volume mount", () => {
    const f = run("P1", `volumes:\n  - /var/run/docker.sock:/var/run/docker.sock`);
    expect(f.some(x => x.rule_id === "P1")).toBe(true);
    const finding = findingFor(f, "P1");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags containerd.sock mount", () => {
    const f = run("P1", `volumes:\n  - /run/containerd/containerd.sock:/sock`);
    expect(f.some(x => x.rule_id === "P1")).toBe(true);
    const finding = findingFor(f, "P1");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags crio.sock", () => {
    const f = run("P1", `volumes:\n  - /run/crio/crio.sock:/var/run/crio.sock`);
    expect(f.some(x => x.rule_id === "P1")).toBe(true);
    const finding = findingFor(f, "P1");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag normal volume", () => {
    expect(run("P1", `volumes:\n  - ./data:/app/data`).filter(x => x.rule_id === "P1").length).toBe(0);
  });
  it("does NOT flag without source code", () => {
    expect(runCtx("P1", ctx()).filter(x => x.rule_id === "P1").length).toBe(0);
  });
});

// ─── P2 — Dangerous Container Capabilities ──────────────────────────────

describe("P2 — Dangerous Container Capabilities", () => {
  it("flags privileged: true", () => {
    const f = run("P2", `privileged: true`);
    expect(f.some(x => x.rule_id === "P2")).toBe(true);
    const finding = findingFor(f, "P2");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags SYS_ADMIN cap", () => {
    const f = run("P2", `capabilities:\n    add:\n      - SYS_ADMIN`);
    expect(f.some(x => x.rule_id === "P2")).toBe(true);
    const finding = findingFor(f, "P2");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags SYS_PTRACE cap", () => {
    const f = run("P2", `capabilities:\n    add:\n      - SYS_PTRACE`);
    expect(f.some(x => x.rule_id === "P2")).toBe(true);
    const finding = findingFor(f, "P2");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags hostPID: true", () => {
    const f = run("P2", `hostPID: true`);
    expect(f.some(x => x.rule_id === "P2")).toBe(true);
    const finding = findingFor(f, "P2");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags hostNetwork: true", () => {
    const f = run("P2", `hostNetwork: true`);
    expect(f.some(x => x.rule_id === "P2")).toBe(true);
    const finding = findingFor(f, "P2");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag normal security context", () => {
    expect(run("P2", `runAsNonRoot: true\nreadOnlyRootFilesystem: true`).filter(x => x.rule_id === "P2").length).toBe(0);
  });
});

// ─── P3 — Cloud Metadata Access ──────────────────────────────────────────

describe("P3 — Cloud Metadata Access", () => {
  it("flags 169.254.169.254", () => {
    const f = run("P3", `fetch('http://169.254.169.254/latest/meta-data/');`);
    expect(f.some(x => x.rule_id === "P3")).toBe(true);
    const finding = findingFor(f, "P3");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags metadata.google.internal", () => {
    const f = run("P3", `fetch('http://metadata.google.internal/computeMetadata/v1/');`);
    expect(f.some(x => x.rule_id === "P3")).toBe(true);
    const finding = findingFor(f, "P3");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags Azure metadata", () => {
    const f = run("P3", `fetch('http://metadata.azure.com/metadata/instance');`);
    expect(f.some(x => x.rule_id === "P3")).toBe(true);
    const finding = findingFor(f, "P3");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag blocking metadata via iptables", () => {
    expect(run("P3", `# iptables -A OUTPUT -d 169.254.169.254 -j REJECT`).filter(x => x.rule_id === "P3").length).toBe(0);
  });
  it("does NOT flag no source code", () => {
    expect(runCtx("P3", ctx()).filter(x => x.rule_id === "P3").length).toBe(0);
  });
});

// ─── P4 — TLS Bypass ────────────────────────────────────────────────────

describe("P4 — TLS Bypass", () => {
  it("flags NODE_TLS_REJECT_UNAUTHORIZED=0", () => {
    const f = run("P4", `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';`);
    expect(f.some(x => x.rule_id === "P4")).toBe(true);
    const finding = findingFor(f, "P4");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags rejectUnauthorized: false", () => {
    const f = run("P4", `https.request({ rejectUnauthorized: false });`);
    expect(f.some(x => x.rule_id === "P4")).toBe(true);
    const finding = findingFor(f, "P4");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags Python verify=False", () => {
    const f = run("P4", `requests.get(url, verify=False)`);
    expect(f.some(x => x.rule_id === "P4")).toBe(true);
    const finding = findingFor(f, "P4");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags Go InsecureSkipVerify", () => {
    const f = run("P4", `tls.Config{InsecureSkipVerify: true}`);
    expect(f.some(x => x.rule_id === "P4")).toBe(true);
    const finding = findingFor(f, "P4");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags curl --insecure", () => {
    const f = run("P4", `execSync("curl -k https://api.example.com");`);
    expect(f.some(x => x.rule_id === "P4")).toBe(true);
    const finding = findingFor(f, "P4");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags ssl.CERT_NONE", () => {
    const f = run("P4", `context = ssl.create_default_context()\ncontext.check_hostname = False\ncontext.verify_mode = ssl.CERT_NONE`);
    expect(f.some(x => x.rule_id === "P4")).toBe(true);
    const finding = findingFor(f, "P4");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag proper TLS config", () => {
    expect(run("P4", `const agent = new https.Agent({ rejectUnauthorized: true, ca: rootCA });`).filter(x => x.rule_id === "P4").length).toBe(0);
  });
});

// ─── P5 — Secrets in Build Layers ────────────────────────────────────────

describe("P5 — Secrets in Build Layers", () => {
  it("flags ARG with PASSWORD", () => {
    const f = run("P5", `FROM node:18\nARG DB_PASSWORD=secret123`);
    expect(f.some(x => x.rule_id === "P5")).toBe(true);
    const finding = findingFor(f, "P5");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags COPY .env", () => {
    const f = run("P5", `FROM node:18\nCOPY .env /app/.env`);
    expect(f.some(x => x.rule_id === "P5")).toBe(true);
    const finding = findingFor(f, "P5");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags ENV with TOKEN", () => {
    const f = run("P5", `FROM node:18\nENV API_TOKEN=sk-abc123`);
    expect(f.some(x => x.rule_id === "P5")).toBe(true);
    const finding = findingFor(f, "P5");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags ARG with SECRET", () => {
    const f = run("P5", `FROM python:3.12\nARG AWS_ACCESS_SECRET=AKIAIOSFODNN7EXAMPLE`);
    expect(f.some(x => x.rule_id === "P5")).toBe(true);
    const finding = findingFor(f, "P5");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag non-secret ARG", () => {
    expect(run("P5", `FROM node:18\nARG NODE_ENV=production`).filter(x => x.rule_id === "P5").length).toBe(0);
  });
});

// ─── P6 — LD_PRELOAD ────────────────────────────────────────────────────

describe("P6 — LD_PRELOAD", () => {
  it("flags LD_PRELOAD set", () => {
    const f = run("P6", `LD_PRELOAD=/tmp/evil.so`);
    expect(f.some(x => x.rule_id === "P6")).toBe(true);
    const finding = findingFor(f, "P6");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags DYLD_INSERT_LIBRARIES", () => {
    const f = run("P6", `DYLD_INSERT_LIBRARIES=/tmp/hook.dylib`);
    expect(f.some(x => x.rule_id === "P6")).toBe(true);
    const finding = findingFor(f, "P6");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags /proc/pid/mem access", () => {
    const f = run("P6", `open('/proc/1234/mem', 'r');`);
    expect(f.some(x => x.rule_id === "P6")).toBe(true);
    const finding = findingFor(f, "P6");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags ptrace attach", () => {
    const f = run("P6", `ptrace(PTRACE_ATTACH, targetPid, 0, 0);`);
    expect(f.some(x => x.rule_id === "P6")).toBe(true);
    const finding = findingFor(f, "P6");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag normal library loading", () => {
    expect(run("P6", `const crypto = require('crypto');`).filter(x => x.rule_id === "P6").length).toBe(0);
  });
});

// ─── P7 — Host Filesystem Mount ──────────────────────────────────────────

describe("P7 — Host Filesystem Mount", () => {
  it("flags root mount", () => {
    const f = run("P7", `volumes:\n  - /:/host-root`);
    expect(f.some(x => x.rule_id === "P7")).toBe(true);
    const finding = findingFor(f, "P7");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags /etc mount", () => {
    const f = run("P7", `volumes:\n  - /etc/:/etc-host`);
    expect(f.some(x => x.rule_id === "P7")).toBe(true);
    const finding = findingFor(f, "P7");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags ~/.ssh mount via hostPath", () => {
    const f = run("P7", `hostPath:\n    path: /home/user/.ssh`);
    expect(f.some(x => x.rule_id === "P7")).toBe(true);
    const finding = findingFor(f, "P7");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag named volume", () => {
    expect(run("P7", `volumes:\n  - app-data:/app/data`).filter(x => x.rule_id === "P7").length).toBe(0);
  });
});

// ─── P8 — ECB Mode / Static IV ──────────────────────────────────────────

describe("P8 — ECB Mode / Static IV", () => {
  it("flags ECB mode cipher", () => {
    const f = run("P8", `const cipher = crypto.createCipheriv('aes-128-ecb', key, null); // ECB mode encrypt`);
    expect(f.some(x => x.rule_id === "P8")).toBe(true);
    const finding = findingFor(f, "P8");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags Math.random for crypto purpose", () => {
    const f = run("P8", `function encryptData(key, secret) { const iv = Math.random().toString(16).slice(2); return cipher(key, iv); }`);
    expect(f.some(x => x.rule_id === "P8")).toBe(true);
    const finding = findingFor(f, "P8");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags static zero IV", () => {
    const f = run("P8", `const iv = Buffer.alloc(16); // static zero IV for encryption nonce`);
    expect(f.some(x => x.rule_id === "P8")).toBe(true);
    const finding = findingFor(f, "P8");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag secure randomBytes IV", () => {
    expect(run("P8", `const iv = crypto.randomBytes(16);`).filter(x => x.rule_id === "P8").length).toBe(0);
  });
});

// ─── P9 — Excessive Container Resource Limits ───────────────────────────

describe("P9 — Excessive Container Resource Limits", () => {
  it("flags unlimited memory", () => {
    const f = run("P9", `memory: unlimited`);
    expect(f.some(x => x.rule_id === "P9")).toBe(true);
    const finding = findingFor(f, "P9");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  // v2 P9 (packages/analyzer/src/rules/implementations/p9-excessive-container-resources/
  // CHARTER.md) recognises canonical k8s/Compose keys (`cpu:`, `memory:`,
  // `limits.cpu`, `--cpus=`). The legacy `cpuLimit:` camelCase alias is not
  // part of any canonical k8s/Docker schema; dropped. Comprehensive CPU-limit
  // coverage lives in the per-rule test suite.
  it("does NOT flag reasonable limit", () => {
    expect(run("P9", `memory: 512Mi\ncpu: "1000m"`).filter(x => x.rule_id === "P9").length).toBe(0);
  });
});

// ─── P10 — Network Host Mode ────────────────────────────────────────────

describe("P10 — Network Host Mode", () => {
  it("flags network_mode: host", () => {
    const f = run("P10", `network_mode: host`);
    expect(f.some(x => x.rule_id === "P10")).toBe(true);
    const finding = findingFor(f, "P10");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags --net=host", () => {
    const f = run("P10", `docker run --net=host myimage`);
    expect(f.some(x => x.rule_id === "P10")).toBe(true);
    const finding = findingFor(f, "P10");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags --network=host", () => {
    const f = run("P10", `docker run --network=host myimage`);
    expect(f.some(x => x.rule_id === "P10")).toBe(true);
    const finding = findingFor(f, "P10");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag bridge network", () => {
    expect(run("P10", `network_mode: bridge`).filter(x => x.rule_id === "P10").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Q — Cross-Ecosystem Emergent
// ═══════════════════════════════════════════════════════════════════════════

// ─── Q1 — Dual-Protocol Schema Loss ─────────────────────────────────────

describe("Q1 — Dual-Protocol Schema Constraint Loss", () => {
  it("flags openapi->mcp conversion without validation", () => {
    const f = run("Q1", `const tools = convertOpenAPIToMCP(spec); // transform rest to mcp tool`);
    expect(f.some(x => x.rule_id === "Q1")).toBe(true);
    const finding = findingFor(f, "Q1");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags graphql->mcp transformation", () => {
    const f = run("Q1", `const tools = transform(graphqlSchema, 'mcp'); // convert graphql to tool`);
    expect(f.some(x => x.rule_id === "Q1")).toBe(true);
    const finding = findingFor(f, "Q1");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag conversion with validation", () => {
    expect(run("Q1", `const tools = convertOpenAPIToMCP(spec); validate(tools); constrain(schema);`).filter(x => x.rule_id === "Q1").length).toBe(0);
  });
});

// ─── Q2 — LangChain Serialization ───────────────────────────────────────

describe("Q2 — LangChain Serialization", () => {
  it("flags langchain deserialize with user input", () => {
    const f = run("Q2", `const chain = langchain.deserialize(userInput);`);
    expect(f.some(x => x.rule_id === "Q2")).toBe(true);
    const finding = findingFor(f, "Q2");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags crewai deserialization", () => {
    const f = run("Q2", `const crew = crewai.from_dict(untrusted); // crewai deserialize`);
    expect(f.some(x => x.rule_id === "Q2")).toBe(true);
    const finding = findingFor(f, "Q2");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags autogen pickle loads", () => {
    const f = run("Q2", `const agent = autogen.loads(pickledData); // autogen deserialize`);
    expect(f.some(x => x.rule_id === "Q2")).toBe(true);
    const finding = findingFor(f, "Q2");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag normal chain creation", () => {
    expect(run("Q2", `const chain = new LLMChain({ prompt, llm });`).filter(x => x.rule_id === "Q2").length).toBe(0);
  });
});

// ─── Q3 — Localhost Hijacking ────────────────────────────────────────────

describe("Q3 — Localhost MCP Service Hijacking", () => {
  it("flags localhost MCP server without auth", () => {
    const f = run("Q3", `server.listen(3000, "localhost"); // MCP tool server`);
    expect(f.some(x => x.rule_id === "Q3")).toBe(true);
    const finding = findingFor(f, "Q3");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags 127.0.0.1 MCP endpoint", () => {
    const f = run("Q3", `const url = "http://127.0.0.1:5000/mcp"; // tool server endpoint`);
    expect(f.some(x => x.rule_id === "Q3")).toBe(true);
    const finding = findingFor(f, "Q3");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag with auth middleware", () => {
    expect(run("Q3", `app.use(authMiddleware);\nserver.listen(3000, "127.0.0.1"); // MCP server with auth`).filter(x => x.rule_id === "Q3").length).toBe(0);
  });
});

// ─── Q4 — IDE Config Injection ───────────────────────────────────────────

describe("Q4 — IDE Config Injection", () => {
  it("flags auto-approve pattern in write context", () => {
    const f = run("Q4", `const config = { enableAllProjectMcpServers: true };\nfs.writeFileSync('.cursor/settings.json', JSON.stringify(config));`);
    expect(f.some(x => x.rule_id === "Q4")).toBe(true);
    const finding = findingFor(f, "Q4");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags case-sensitivity bypass (CVE-2025-59944)", () => {
    // v2 Q4 requires a real write op — bare string literal is insufficient.
    const f = run("Q4", `import fs from "node:fs";\nexport function x(body) { fs.writeFileSync('/Users/bob/.cursor/MCP.JSON', JSON.stringify(body)); }`);
    expect(f.some(x => x.rule_id === "Q4")).toBe(true);
    const finding = findingFor(f, "Q4");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag reading config", () => {
    expect(run("Q4", `const c = fs.readFileSync('.vscode/settings.json');`).filter(x => x.rule_id === "Q4").length).toBe(0);
  });
});

// ─── Q5 — MCP Gateway Trust Delegation Confusion ────────────────────────

describe("Q5 — MCP Gateway Trust Delegation Confusion", () => {
  it("flags gateway forwarding trust without check", () => {
    const f = run("Q5", `gateway.trust(upstream); forward(token); delegate(creds);`);
    expect(f.some(x => x.rule_id === "Q5")).toBe(true);
    const finding = findingFor(f, "Q5");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags inheriting upstream auth", () => {
    const f = run("Q5", `const t = upstream.auth; origin.trust(t); reuse(t); inherit(t);`);
    expect(f.some(x => x.rule_id === "Q5")).toBe(true);
    const finding = findingFor(f, "Q5");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag re-validated gateway auth", () => {
    expect(run("Q5", `const token = gateway.auth; validate(token); scope(token, ['read']); limit(token);`).filter(x => x.rule_id === "Q5").length).toBe(0);
  });
});

// ─── Q6 — Agent Impersonation ────────────────────────────────────────────

describe("Q6 — Agent Identity Impersonation", () => {
  it("flags Anthropic in serverInfo", () => {
    const f = run("Q6", `serverInfo: { name: "Anthropic Official Server" }`);
    expect(f.some(x => x.rule_id === "Q6")).toBe(true);
    const finding = findingFor(f, "Q6");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags OpenAI impersonation", () => {
    const f = run("Q6", `serverInfo: { name: "OpenAI Verified MCP" }`);
    expect(f.some(x => x.rule_id === "Q6")).toBe(true);
    const finding = findingFor(f, "Q6");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag unique server name", () => {
    expect(run("Q6", `serverInfo: { name: "my-custom-mcp-server" }`).filter(x => x.rule_id === "Q6").length).toBe(0);
  });
});

// ─── Q7 — Desktop Extension Privilege Chain ──────────────────────────────

describe("Q7 — Desktop Extension Privilege Chain (DXT)", () => {
  it("flags browser extension privilege escalation", () => {
    const f = run("Q7", `extension.privilege('filesystem'); requestPermission('access', { escalate: true, elevate: true });`);
    expect(f.some(x => x.rule_id === "Q7")).toBe(true);
    const finding = findingFor(f, "Q7");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags native messaging to MCP bridge", () => {
    const f = run("Q7", `chrome.runtime.sendNativeMessage('mcp-bridge', data); // browser.runtime bridge to tool server`);
    expect(f.some(x => x.rule_id === "Q7")).toBe(true);
    const finding = findingFor(f, "Q7");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag normal extension API usage", () => {
    expect(run("Q7", `chrome.tabs.query({ active: true });`).filter(x => x.rule_id === "Q7").length).toBe(0);
  });
});

// ─── Q8 — Cross-Protocol Auth Confusion ──────────────────────────────────

describe("Q8 — Cross-Protocol Authentication Confusion", () => {
  it("flags HTTP token reused for MCP", () => {
    const f = run("Q8", `// Reuse http bearer token for MCP SSE transport\nconst mcpAuth = httpToken;`);
    expect(f.some(x => x.rule_id === "Q8")).toBe(true);
    const finding = findingFor(f, "Q8");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags oauth token shared across protocols", () => {
    const f = run("Q8", `const sseAuth = rest.token; // reuse http oauth for mcp sse same copy`);
    expect(f.some(x => x.rule_id === "Q8")).toBe(true);
    const finding = findingFor(f, "Q8");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag protocol-specific auth", () => {
    expect(run("Q8", `const mcpToken = generateMCPToken(user);`).filter(x => x.rule_id === "Q8").length).toBe(0);
  });
});

// ─── Q9 — DAG Manipulation ──────────────────────────────────────────────

describe("Q9 — Agentic Workflow DAG Manipulation", () => {
  it("flags user input modifying workflow graph", () => {
    const f = run("Q9", `workflow.add_edge(userInput, nextNode);`);
    expect(f.some(x => x.rule_id === "Q9")).toBe(true);
    const finding = findingFor(f, "Q9");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags dynamic workflow from external input", () => {
    const f = run("Q9", `const graph = langgraph.StateGraph(config); graph.add_node(user_request, dynamic);`);
    expect(f.some(x => x.rule_id === "Q9")).toBe(true);
    const finding = findingFor(f, "Q9");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag static workflow definition", () => {
    expect(run("Q9", `const graph = new StateGraph(); graph.add_node("agent", agentFn); graph.add_edge("start", "agent");`).filter(x => x.rule_id === "Q9").length).toBe(0);
  });
});

// ─── Q10 — Agent Memory Poisoning ───────────────────────────────────────

describe("Q10 — Agent Memory Poisoning", () => {
  it("flags storing instructions in memory", () => {
    const f = runCtx("Q10", ctx({ tools: [{ name: "memorize", description: "Store instruction directive in long-term memory for the agent to remember", input_schema: null }] }));
    expect(f.some(x => x.rule_id === "Q10")).toBe(true);
    const finding = findingFor(f, "Q10");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags persisting behavioral rules", () => {
    const f = runCtx("Q10", ctx({ tools: [{ name: "persist_rule", description: "Save a behavior policy rule to persist in agent memory", input_schema: null }] }));
    expect(f.some(x => x.rule_id === "Q10")).toBe(true);
    const finding = findingFor(f, "Q10");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag storing factual data", () => {
    expect(runCtx("Q10", ctx({ tools: [{ name: "save_note", description: "Save a text note", input_schema: null }] })).filter(x => x.rule_id === "Q10").length).toBe(0);
  });
});

// ─── Q11 — Code Suggestion Poisoning ────────────────────────────────────

describe("Q11 — Code Suggestion Poisoning", () => {
  it("flags tool injecting code suggestions", () => {
    const f = run("Q11", `toolResponse.code_suggestion = inject_payload(suggestion);`);
    expect(f.some(x => x.rule_id === "Q11")).toBe(true);
    const finding = findingFor(f, "Q11");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags MCP output with code insert", () => {
    const f = run("Q11", `const result = mcp.response.output; code.suggestion.inject(result);`);
    expect(f.some(x => x.rule_id === "Q11")).toBe(true);
    const finding = findingFor(f, "Q11");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag normal code completion", () => {
    expect(run("Q11", `const result = processQuery(input); return { text: result };`).filter(x => x.rule_id === "Q11").length).toBe(0);
  });
});

// ─── Q12 — Browser Extension <-> MCP Bridge ─────────────────────────────

describe("Q12 — Browser Extension MCP Bridge", () => {
  it("flags browser runtime messaging to MCP", () => {
    const f = run("Q12", `chrome.runtime.sendMessage(extensionId, { action: 'mcp_call', tool: toolName });`);
    expect(f.some(x => x.rule_id === "Q12")).toBe(true);
    const finding = findingFor(f, "Q12");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag normal message without mcp", () => {
    expect(run("Q12", `chrome.runtime.sendMessage({ action: 'open_tab' });`).filter(x => x.rule_id === "Q12").length).toBe(0);
  });
});

// ─── Q13 — MCP Bridge Supply Chain ──────────────────────────────────────

describe("Q13 — MCP Bridge Supply Chain", () => {
  it("flags unpinned npx mcp-remote", () => {
    const f = run("Q13", `"command": "npx mcp-remote https://api.example.com"`);
    expect(f.some(x => x.rule_id === "Q13")).toBe(true);
    const finding = findingFor(f, "Q13");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags caret version dependency", () => {
    const f = run("Q13", `"mcp-remote": "^1.0.0"`);
    expect(f.some(x => x.rule_id === "Q13")).toBe(true);
    const finding = findingFor(f, "Q13");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags tilde version dependency", () => {
    const f = run("Q13", `"mcp-gateway": "~2.1.0"`);
    expect(f.some(x => x.rule_id === "Q13")).toBe(true);
    const finding = findingFor(f, "Q13");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag pinned version", () => {
    expect(run("Q13", `"mcp-remote": "1.2.3"`).filter(x => x.rule_id === "Q13").length).toBe(0);
  });
});

// ─── Q14 — Cross-Language Serialization Mismatch ─────────────────────────

describe("Q14 — Cross-Language Serialization Mismatch", () => {
  it("flags cross-language serialization", () => {
    const f = run("Q14", `// serialize from python to javascript\nconst data = marshal(pythonObj); const jsObj = deserialize(data, 'javascript');`);
    expect(f.some(x => x.rule_id === "Q14")).toBe(true);
    const finding = findingFor(f, "Q14");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag same-language serialization", () => {
    expect(run("Q14", `const data = JSON.stringify(obj); const parsed = JSON.parse(data);`).filter(x => x.rule_id === "Q14").length).toBe(0);
  });
});

// ─── Q15 — Workflow Persistence Hijacking ────────────────────────────────

describe("Q15 — Workflow Persistence Hijacking", () => {
  it("flags unprotected workflow checkpoint", () => {
    const f = run("Q15", `checkpoint(workflow_state, '/tmp/wf.json'); // persist progress to file`);
    expect(f.some(x => x.rule_id === "Q15")).toBe(true);
    const finding = findingFor(f, "Q15");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags workflow snapshot without signing", () => {
    const f = run("Q15", `save state to file for later; // snapshot workflow to disk`);
    expect(f.some(x => x.rule_id === "Q15")).toBe(true);
    const finding = findingFor(f, "Q15");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag encrypted checkpoint", () => {
    expect(run("Q15", `const encrypted = encrypt(state); checkpoint(encrypted, path); verify(hash);`).filter(x => x.rule_id === "Q15").length).toBe(0);
  });
});
