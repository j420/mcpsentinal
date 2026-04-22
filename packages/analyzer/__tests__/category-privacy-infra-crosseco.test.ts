/**
 * Categories: Data Privacy (O1-O10) + Infrastructure (P1-P10) + Cross-Ecosystem (Q1-Q15) — 62 tests
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

// ─── O — Data Privacy ──────────────────────────────────────────────────────

describe("O1 — Steganographic Exfiltration", () => {
  it("flags steg embedding", () => {
    const f = run("O1", `steg.embed(image, secretData, { lsb: true });`);
    expect(f.some(x => x.rule_id === "O1")).toBe(true);
    const finding = findingFor(f, "O1");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags pixel-level hiding", () => {
    const f = run("O1", `pixel.encode(data, 'hide secret payload');`);
    expect(f.some(x => x.rule_id === "O1")).toBe(true);
    const finding = findingFor(f, "O1");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag normal image processing", () => { expect(run("O1", `const img = sharp(input).resize(100).toFile(output);`).filter(x => x.rule_id === "O1").length).toBe(0); });
});

describe("O2 — HTTP Header Covert Channel", () => {
  it("flags encoded secret in custom header", () => {
    const f = run("O2", `res.setHeader('X-Data', Buffer.from(secret).toString('base64'));`);
    expect(f.some(x => x.rule_id === "O2")).toBe(true);
    const finding = findingFor(f, "O2");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag standard headers", () => { expect(run("O2", `res.setHeader('Content-Type', 'application/json');`).filter(x => x.rule_id === "O2").length).toBe(0); });
});

describe("O3 — AI-Mediated Exfiltration", () => {
  it("flags sensitive data encoded in tool args", () => {
    const f = run("O3", `const payload = base64Encode(tool.execute({ input: secretData }));`);
    expect(f.some(x => x.rule_id === "O3")).toBe(true);
    const finding = findingFor(f, "O3");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
});

describe("O5 — Env Var Harvesting", () => {
  it("flags JSON.stringify(process.env)", () => {
    const f = run("O5", `JSON.stringify(process.env)`);
    expect(f.some(x => x.rule_id === "O5")).toBe(true);
    const finding = findingFor(f, "O5");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags Python os.environ.items()", () => {
    const f = run("O5", `for k, v in os.environ.items():\n    print(k, v)`);
    expect(f.some(x => x.rule_id === "O5")).toBe(true);
    const finding = findingFor(f, "O5");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag specific env access", () => { expect(run("O5", `const port = process.env.PORT;`).filter(x => x.rule_id === "O5").length).toBe(0); });
});

describe("O6 — Clipboard Access", () => {
  it("flags clipboard read", () => {
    const f = run("O6", `const text = clipboard.readText();`);
    expect(f.some(x => x.rule_id === "O6")).toBe(true);
    const finding = findingFor(f, "O6");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags pbpaste read", () => {
    const f = run("O6", `const stolen = pbpaste(); // clipboard paste read`);
    expect(f.some(x => x.rule_id === "O6")).toBe(true);
    const finding = findingFor(f, "O6");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
});

describe("O7 — Cross-Session Data Leakage", () => {
  it("flags module-level mutable cache", () => {
    const f = run("O7", `const sessionCache = new Map();\nmodule.exports = { sessionCache };`);
    expect(f.some(x => x.rule_id === "O7")).toBe(true);
    const finding = findingFor(f, "O7");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag per-request state", () => { expect(run("O7", `app.get('/', (req, res) => { const state = new Map(); });`).filter(x => x.rule_id === "O7").length).toBe(0); });
});

describe("O8 — Screenshot/Screen Capture", () => {
  it("flags screenshot capability", () => {
    const f = run("O8", `const img = await captureScreen();`);
    expect(f.some(x => x.rule_id === "O8")).toBe(true);
    const finding = findingFor(f, "O8");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags desktopCapturer", () => {
    const f = run("O8", `desktopCapturer.getSources({ types: ['screen'] });`);
    expect(f.some(x => x.rule_id === "O8")).toBe(true);
    const finding = findingFor(f, "O8");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
});

describe("O9 — Ambient Credential Exploitation", () => {
  it("flags default credentials", () => {
    const f = run("O9", `const creds = await google.auth.getApplicationDefault(); // default_credentials`);
    expect(f.some(x => x.rule_id === "O9")).toBe(true);
    const finding = findingFor(f, "O9");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags GOOGLE_APPLICATION_CREDENTIALS", () => {
    const f = run("O9", `process.env.GOOGLE_APPLICATION_CREDENTIALS = '/path/to/key.json';`);
    expect(f.some(x => x.rule_id === "O9")).toBe(true);
    const finding = findingFor(f, "O9");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
});

describe("O10 — Keylogging", () => {
  it("flags keyboard hook", () => {
    const f = run("O10", `document.addEventListener('keydown', keylogHandler);`);
    expect(f.some(x => x.rule_id === "O10")).toBe(true);
    const finding = findingFor(f, "O10");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
});

// ─── P — Infrastructure ────────────────────────────────────────────────────

describe("P1 — Docker Socket Mount", () => {
  it("flags docker.sock volume", () => {
    const f = run("P1", `volumes:\n  - /var/run/docker.sock:/var/run/docker.sock`);
    expect(f.some(x => x.rule_id === "P1")).toBe(true);
    const finding = findingFor(f, "P1");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags containerd.sock", () => {
    const f = run("P1", `volumes:\n  - /run/containerd/containerd.sock:/sock`);
    expect(f.some(x => x.rule_id === "P1")).toBe(true);
    const finding = findingFor(f, "P1");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag normal volume", () => { expect(run("P1", `volumes:\n  - ./data:/app/data`).filter(x => x.rule_id === "P1").length).toBe(0); });
});

describe("P2 — Dangerous Capabilities", () => {
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
  it("flags hostPID", () => {
    const f = run("P2", `hostPID: true`);
    expect(f.some(x => x.rule_id === "P2")).toBe(true);
    const finding = findingFor(f, "P2");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag normal security context", () => { expect(run("P2", `runAsNonRoot: true\nreadOnlyRootFilesystem: true`).filter(x => x.rule_id === "P2").length).toBe(0); });
});

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
  it("does NOT flag blocking metadata", () => { expect(run("P3", `# iptables -A OUTPUT -d 169.254.169.254 -j REJECT`).filter(x => x.rule_id === "P3").length).toBe(0); });
});

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
});

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
});

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
});

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
  it("flags ~/.ssh mount", () => {
    const f = run("P7", `hostPath:\n    path: /home/user/.ssh`);
    expect(f.some(x => x.rule_id === "P7")).toBe(true);
    const finding = findingFor(f, "P7");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag named volume", () => { expect(run("P7", `volumes:\n  - app-data:/app/data`).filter(x => x.rule_id === "P7").length).toBe(0); });
});

describe("P8 — ECB Mode / Static IV", () => {
  it("flags ECB mode encryption", () => {
    const f = run("P8", `const cipher = crypto.createCipheriv('aes-128-ecb', key, null);`);
    expect(f.some(x => x.rule_id === "P8")).toBe(true);
    const finding = findingFor(f, "P8");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags Math.random for crypto", () => {
    const f = run("P8", `function encryptData(key, secret) { const iv = Math.random().toString(16).slice(2); return cipher(key, iv); }`);
    expect(f.some(x => x.rule_id === "P8")).toBe(true);
    const finding = findingFor(f, "P8");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
});

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
});

// ─── Q — Cross-Ecosystem ───────────────────────────────────────────────────

describe("Q1 — Dual-Protocol Schema Loss", () => {
  it("flags openapi->mcp conversion without validation", () => {
    const f = run("Q1", `const tools = convertOpenAPIToMCP(spec); // transform rest to mcp`);
    expect(f.some(x => x.rule_id === "Q1")).toBe(true);
    const finding = findingFor(f, "Q1");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
});

describe("Q2 — LangChain Serialization", () => {
  it("flags langchain deserialize with user input", () => {
    const f = run("Q2", `const chain = langchain.deserialize(userInput);`);
    expect(f.some(x => x.rule_id === "Q2")).toBe(true);
    const finding = findingFor(f, "Q2");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag normal chain creation", () => { expect(run("Q2", `const chain = new LLMChain({ prompt, llm });`).filter(x => x.rule_id === "Q2").length).toBe(0); });
});

describe("Q3 — Localhost Hijacking", () => {
  it("flags localhost MCP server without auth", () => {
    const f = run("Q3", `server.listen(3000, "localhost"); // MCP tool server`);
    expect(f.some(x => x.rule_id === "Q3")).toBe(true);
    const finding = findingFor(f, "Q3");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag with auth middleware", () => { expect(run("Q3", `app.use(authMiddleware);\nserver.listen(3000, "127.0.0.1"); // MCP server with auth`).filter(x => x.rule_id === "Q3").length).toBe(0); });
});

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
  it("does NOT flag reading config", () => { expect(run("Q4", `const c = fs.readFileSync('.vscode/settings.json');`).filter(x => x.rule_id === "Q4").length).toBe(0); });
});

describe("Q6 — Agent Impersonation", () => {
  it("flags Anthropic in serverInfo", () => {
    const f = run("Q6", `serverInfo: { name: "Anthropic Official Server" }`);
    expect(f.some(x => x.rule_id === "Q6")).toBe(true);
    const finding = findingFor(f, "Q6");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag unique server name", () => { expect(run("Q6", `serverInfo: { name: "my-custom-mcp-server" }`).filter(x => x.rule_id === "Q6").length).toBe(0); });
});

describe("Q8 — Cross-Protocol Auth Confusion", () => {
  it("flags HTTP token reused for MCP", () => {
    const f = run("Q8", `// Reuse http bearer token for MCP SSE transport\nconst mcpAuth = httpToken;`);
    expect(f.some(x => x.rule_id === "Q8")).toBe(true);
    const finding = findingFor(f, "Q8");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
});

describe("Q9 — DAG Manipulation", () => {
  it("flags user input modifying workflow", () => {
    const f = run("Q9", `workflow.add_edge(userInput, nextNode);`);
    expect(f.some(x => x.rule_id === "Q9")).toBe(true);
    const finding = findingFor(f, "Q9");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
});

describe("Q11 — Code Suggestion Poisoning", () => {
  it("flags tool injecting code suggestions", () => {
    const f = run("Q11", `toolResponse.code_suggestion = inject_payload(suggestion);`);
    expect(f.some(x => x.rule_id === "Q11")).toBe(true);
    const finding = findingFor(f, "Q11");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
});

describe("Q13 — MCP Bridge Supply Chain", () => {
  it("flags unpinned npx mcp-remote", () => {
    const f = run("Q13", `"command": "npx mcp-remote https://api.example.com"`);
    expect(f.some(x => x.rule_id === "Q13")).toBe(true);
    const finding = findingFor(f, "Q13");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("flags caret version", () => {
    const f = run("Q13", `"mcp-remote": "^1.0.0"`);
    expect(f.some(x => x.rule_id === "Q13")).toBe(true);
    const finding = findingFor(f, "Q13");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
  it("does NOT flag pinned version", () => { expect(run("Q13", `"mcp-remote": "1.2.3"`).filter(x => x.rule_id === "Q13").length).toBe(0); });
});

describe("Q15 — Workflow Persistence Hijacking", () => {
  it("flags unprotected workflow checkpoint", () => {
    const f = run("Q15", `checkpoint(workflow_state, '/tmp/wf.json'); // persist progress to file`);
    expect(f.some(x => x.rule_id === "Q15")).toBe(true);
    const finding = findingFor(f, "Q15");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.20, 0.99);
  });
});
