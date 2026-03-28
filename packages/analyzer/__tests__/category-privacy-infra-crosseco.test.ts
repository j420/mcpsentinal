/**
 * Categories: Data Privacy (O1-O10) + Infrastructure (P1-P10) + Cross-Ecosystem (Q1-Q15) — 62 tests
 */
import { describe, it, expect } from "vitest";
import type { AnalysisContext } from "../src/engine.js";
import { getTypedRule } from "../src/rules/base.js";
import "../src/rules/index.js";

function ctx(overrides: Partial<AnalysisContext> = {}): AnalysisContext {
  return { server: { id: "t", name: "test", description: null, github_url: null }, tools: [], source_code: null, dependencies: [], connection_metadata: null, ...overrides };
}
function run(id: string, src: string) { return getTypedRule(id)!.analyze(ctx({ source_code: src })); }
function runCtx(id: string, c: AnalysisContext) { return getTypedRule(id)!.analyze(c); }

// ─── O — Data Privacy ──────────────────────────────────────────────────────

describe("O1 — Steganographic Exfiltration", () => {
  it("flags steg embedding", () => { expect(run("O1", `steg.embed(image, secretData, { lsb: true });`).some(x => x.rule_id === "O1")).toBe(true); });
  it("flags pixel-level hiding", () => { expect(run("O1", `pixel.encode(data, 'hide secret payload');`).some(x => x.rule_id === "O1")).toBe(true); });
  it("does NOT flag normal image processing", () => { expect(run("O1", `const img = sharp(input).resize(100).toFile(output);`).filter(x => x.rule_id === "O1").length).toBe(0); });
});

describe("O2 — HTTP Header Covert Channel", () => {
  it("flags encoded secret in custom header", () => { expect(run("O2", `res.setHeader('X-Data', Buffer.from(secret).toString('base64'));`).some(x => x.rule_id === "O2")).toBe(true); });
  it("does NOT flag standard headers", () => { expect(run("O2", `res.setHeader('Content-Type', 'application/json');`).filter(x => x.rule_id === "O2").length).toBe(0); });
});

describe("O3 — AI-Mediated Exfiltration", () => {
  it("flags sensitive data encoded in tool args", () => { expect(run("O3", `const payload = base64Encode(tool.execute({ input: secretData }));`).some(x => x.rule_id === "O3")).toBe(true); });
});

describe("O5 — Env Var Harvesting", () => {
  it("flags JSON.stringify(process.env)", () => { expect(run("O5", `JSON.stringify(process.env)`).some(x => x.rule_id === "O5")).toBe(true); });
  it("flags Python os.environ.items()", () => { expect(run("O5", `for k, v in os.environ.items():\n    print(k, v)`).some(x => x.rule_id === "O5")).toBe(true); });
  it("does NOT flag specific env access", () => { expect(run("O5", `const port = process.env.PORT;`).filter(x => x.rule_id === "O5").length).toBe(0); });
});

describe("O6 — Clipboard Access", () => {
  it("flags clipboard read", () => { expect(run("O6", `const text = clipboard.readText();`).some(x => x.rule_id === "O6")).toBe(true); });
  it("flags pbpaste read", () => { expect(run("O6", `const stolen = pbpaste(); // clipboard paste read`).some(x => x.rule_id === "O6")).toBe(true); });
});

describe("O7 — Cross-Session Data Leakage", () => {
  it("flags module-level mutable cache", () => { expect(run("O7", `const sessionCache = new Map();\nmodule.exports = { sessionCache };`).some(x => x.rule_id === "O7")).toBe(true); });
  it("does NOT flag per-request state", () => { expect(run("O7", `app.get('/', (req, res) => { const state = new Map(); });`).filter(x => x.rule_id === "O7").length).toBe(0); });
});

describe("O8 — Screenshot/Screen Capture", () => {
  it("flags screenshot capability", () => { expect(run("O8", `const img = await captureScreen();`).some(x => x.rule_id === "O8")).toBe(true); });
  it("flags desktopCapturer", () => { expect(run("O8", `desktopCapturer.getSources({ types: ['screen'] });`).some(x => x.rule_id === "O8")).toBe(true); });
});

describe("O9 — Ambient Credential Exploitation", () => {
  it("flags default credentials", () => { expect(run("O9", `const creds = await google.auth.getApplicationDefault(); // default_credentials`).some(x => x.rule_id === "O9")).toBe(true); });
  it("flags GOOGLE_APPLICATION_CREDENTIALS", () => { expect(run("O9", `process.env.GOOGLE_APPLICATION_CREDENTIALS = '/path/to/key.json';`).some(x => x.rule_id === "O9")).toBe(true); });
});

describe("O10 — Keylogging", () => {
  it("flags keyboard hook", () => { expect(run("O10", `document.addEventListener('keydown', keylogHandler);`).some(x => x.rule_id === "O10")).toBe(true); });
});

// ─── P — Infrastructure ────────────────────────────────────────────────────

describe("P1 — Docker Socket Mount", () => {
  it("flags docker.sock volume", () => { expect(run("P1", `volumes:\n  - /var/run/docker.sock:/var/run/docker.sock`).some(x => x.rule_id === "P1")).toBe(true); });
  it("flags containerd.sock", () => { expect(run("P1", `volumes:\n  - /run/containerd/containerd.sock:/sock`).some(x => x.rule_id === "P1")).toBe(true); });
  it("does NOT flag normal volume", () => { expect(run("P1", `volumes:\n  - ./data:/app/data`).filter(x => x.rule_id === "P1").length).toBe(0); });
});

describe("P2 — Dangerous Capabilities", () => {
  it("flags privileged: true", () => { expect(run("P2", `privileged: true`).some(x => x.rule_id === "P2")).toBe(true); });
  it("flags SYS_ADMIN cap", () => { expect(run("P2", `capabilities:\n    add:\n      - SYS_ADMIN`).some(x => x.rule_id === "P2")).toBe(true); });
  it("flags hostPID", () => { expect(run("P2", `hostPID: true`).some(x => x.rule_id === "P2")).toBe(true); });
  it("does NOT flag normal security context", () => { expect(run("P2", `runAsNonRoot: true\nreadOnlyRootFilesystem: true`).filter(x => x.rule_id === "P2").length).toBe(0); });
});

describe("P3 — Cloud Metadata Access", () => {
  it("flags 169.254.169.254", () => { expect(run("P3", `fetch('http://169.254.169.254/latest/meta-data/');`).some(x => x.rule_id === "P3")).toBe(true); });
  it("flags metadata.google.internal", () => { expect(run("P3", `fetch('http://metadata.google.internal/computeMetadata/v1/');`).some(x => x.rule_id === "P3")).toBe(true); });
  it("does NOT flag blocking metadata", () => { expect(run("P3", `# iptables -A OUTPUT -d 169.254.169.254 -j REJECT`).filter(x => x.rule_id === "P3").length).toBe(0); });
});

describe("P4 — TLS Bypass", () => {
  it("flags NODE_TLS_REJECT_UNAUTHORIZED=0", () => { expect(run("P4", `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';`).some(x => x.rule_id === "P4")).toBe(true); });
  it("flags rejectUnauthorized: false", () => { expect(run("P4", `https.request({ rejectUnauthorized: false });`).some(x => x.rule_id === "P4")).toBe(true); });
  it("flags Python verify=False", () => { expect(run("P4", `requests.get(url, verify=False)`).some(x => x.rule_id === "P4")).toBe(true); });
  it("flags Go InsecureSkipVerify", () => { expect(run("P4", `tls.Config{InsecureSkipVerify: true}`).some(x => x.rule_id === "P4")).toBe(true); });
  it("flags curl --insecure", () => { expect(run("P4", `execSync("curl -k https://api.example.com");`).some(x => x.rule_id === "P4")).toBe(true); });
});

describe("P5 — Secrets in Build Layers", () => {
  it("flags ARG with PASSWORD", () => { expect(run("P5", `FROM node:18\nARG DB_PASSWORD=secret123`).some(x => x.rule_id === "P5")).toBe(true); });
  it("flags COPY .env", () => { expect(run("P5", `FROM node:18\nCOPY .env /app/.env`).some(x => x.rule_id === "P5")).toBe(true); });
  it("flags ENV with TOKEN", () => { expect(run("P5", `FROM node:18\nENV API_TOKEN=sk-abc123`).some(x => x.rule_id === "P5")).toBe(true); });
});

describe("P6 — LD_PRELOAD", () => {
  it("flags LD_PRELOAD set", () => { expect(run("P6", `LD_PRELOAD=/tmp/evil.so`).some(x => x.rule_id === "P6")).toBe(true); });
  it("flags DYLD_INSERT_LIBRARIES", () => { expect(run("P6", `DYLD_INSERT_LIBRARIES=/tmp/hook.dylib`).some(x => x.rule_id === "P6")).toBe(true); });
  it("flags /proc/pid/mem access", () => { expect(run("P6", `open('/proc/1234/mem', 'r');`).some(x => x.rule_id === "P6")).toBe(true); });
});

describe("P7 — Host Filesystem Mount", () => {
  it("flags root mount", () => { expect(run("P7", `volumes:\n  - /:/host-root`).some(x => x.rule_id === "P7")).toBe(true); });
  it("flags /etc mount", () => { expect(run("P7", `volumes:\n  - /etc/:/etc-host`).some(x => x.rule_id === "P7")).toBe(true); });
  it("flags ~/.ssh mount", () => { expect(run("P7", `hostPath:\n    path: /home/user/.ssh`).some(x => x.rule_id === "P7")).toBe(true); });
  it("does NOT flag named volume", () => { expect(run("P7", `volumes:\n  - app-data:/app/data`).filter(x => x.rule_id === "P7").length).toBe(0); });
});

describe("P8 — ECB Mode / Static IV", () => {
  it("flags ECB mode encryption", () => { expect(run("P8", `// ECB mode cipher is insecure\nconst mode = "ECB";\nencrypt(data, key, { mode: ECB });`).some(x => x.rule_id === "P8")).toBe(true); });
  it("flags Math.random for crypto", () => { expect(run("P8", `const iv = Math.random().toString(16).slice(2); // use as IV for AES`).some(x => x.rule_id === "P8")).toBe(true); });
});

describe("P10 — Network Host Mode", () => {
  it("flags network_mode: host", () => { expect(run("P10", `network_mode: host`).some(x => x.rule_id === "P10")).toBe(true); });
  it("flags --net=host", () => { expect(run("P10", `docker run --net=host myimage`).some(x => x.rule_id === "P10")).toBe(true); });
});

// ─── Q — Cross-Ecosystem ───────────────────────────────────────────────────

describe("Q1 — Dual-Protocol Schema Loss", () => {
  it("flags openapi→mcp conversion without validation", () => { expect(run("Q1", `const tools = convertOpenAPIToMCP(spec); // transform rest to mcp`).some(x => x.rule_id === "Q1")).toBe(true); });
});

describe("Q2 — LangChain Serialization", () => {
  it("flags langchain deserialize with user input", () => { expect(run("Q2", `const chain = langchain.deserialize(userInput);`).some(x => x.rule_id === "Q2")).toBe(true); });
  it("does NOT flag normal chain creation", () => { expect(run("Q2", `const chain = new LLMChain({ prompt, llm });`).filter(x => x.rule_id === "Q2").length).toBe(0); });
});

describe("Q3 — Localhost Hijacking", () => {
  it("flags localhost MCP server without auth", () => { expect(run("Q3", `server.listen(3000, "localhost"); // MCP tool server`).some(x => x.rule_id === "Q3")).toBe(true); });
  it("does NOT flag with auth middleware", () => { expect(run("Q3", `app.use(authMiddleware);\nserver.listen(3000, "127.0.0.1"); // MCP server with auth`).filter(x => x.rule_id === "Q3").length).toBe(0); });
});

describe("Q4 — IDE Config Injection", () => {
  it("flags auto-approve pattern in write context", () => { expect(run("Q4", `const config = { enableAllProjectMcpServers: true };\nfs.writeFileSync('.cursor/settings.json', JSON.stringify(config));`).some(x => x.rule_id === "Q4")).toBe(true); });
  it("flags case-sensitivity bypass", () => { expect(run("Q4", `const p = ".cursor/MCP.Json";`).some(x => x.rule_id === "Q4")).toBe(true); });
  it("does NOT flag reading config", () => { expect(run("Q4", `const c = fs.readFileSync('.vscode/settings.json');`).filter(x => x.rule_id === "Q4").length).toBe(0); });
});

describe("Q6 — Agent Impersonation", () => {
  it("flags Anthropic in serverInfo", () => { expect(run("Q6", `serverInfo: { name: "Anthropic Official Server" }`).some(x => x.rule_id === "Q6")).toBe(true); });
  it("does NOT flag unique server name", () => { expect(run("Q6", `serverInfo: { name: "my-custom-mcp-server" }`).filter(x => x.rule_id === "Q6").length).toBe(0); });
});

describe("Q8 — Cross-Protocol Auth Confusion", () => {
  it("flags HTTP token reused for MCP", () => { expect(run("Q8", `// Reuse http bearer token for MCP SSE transport\nconst mcpAuth = httpToken;`).some(x => x.rule_id === "Q8")).toBe(true); });
});

describe("Q9 — DAG Manipulation", () => {
  it("flags user input modifying workflow", () => { expect(run("Q9", `workflow.add_edge(userInput, nextNode);`).some(x => x.rule_id === "Q9")).toBe(true); });
});

describe("Q11 — Code Suggestion Poisoning", () => {
  it("flags tool injecting code suggestions", () => { expect(run("Q11", `toolResponse.code_suggestion = inject_payload(suggestion);`).some(x => x.rule_id === "Q11")).toBe(true); });
});

describe("Q13 — MCP Bridge Supply Chain", () => {
  it("flags unpinned npx mcp-remote", () => { expect(run("Q13", `"command": "npx mcp-remote https://api.example.com"`).some(x => x.rule_id === "Q13")).toBe(true); });
  it("flags caret version", () => { expect(run("Q13", `"mcp-remote": "^1.0.0"`).some(x => x.rule_id === "Q13")).toBe(true); });
  it("does NOT flag pinned version", () => { expect(run("Q13", `"mcp-remote": "1.2.3"`).filter(x => x.rule_id === "Q13").length).toBe(0); });
});

describe("Q15 — Workflow Persistence Hijacking", () => {
  it("flags unprotected workflow checkpoint", () => { expect(run("Q15", `checkpoint(workflow_state, '/tmp/wf.json'); // persist progress to file`).some(x => x.rule_id === "Q15")).toBe(true); });
});
