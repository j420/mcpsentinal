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
    expect(run("P1", `volumes:\n  - /var/run/docker.sock:/var/run/docker.sock`).some(x => x.rule_id === "P1")).toBe(true);
  });
  it("flags containerd.sock mount", () => {
    expect(run("P1", `volumes:\n  - /run/containerd/containerd.sock:/sock`).some(x => x.rule_id === "P1")).toBe(true);
  });
  it("flags crio.sock", () => {
    expect(run("P1", `volumes:\n  - /run/crio/crio.sock:/var/run/crio.sock`).some(x => x.rule_id === "P1")).toBe(true);
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
    expect(run("P2", `privileged: true`).some(x => x.rule_id === "P2")).toBe(true);
  });
  it("flags SYS_ADMIN cap", () => {
    expect(run("P2", `capabilities:\n    add:\n      - SYS_ADMIN`).some(x => x.rule_id === "P2")).toBe(true);
  });
  it("flags SYS_PTRACE cap", () => {
    expect(run("P2", `capabilities:\n    add:\n      - SYS_PTRACE`).some(x => x.rule_id === "P2")).toBe(true);
  });
  it("flags hostPID: true", () => {
    expect(run("P2", `hostPID: true`).some(x => x.rule_id === "P2")).toBe(true);
  });
  it("flags hostNetwork: true", () => {
    expect(run("P2", `hostNetwork: true`).some(x => x.rule_id === "P2")).toBe(true);
  });
  it("does NOT flag normal security context", () => {
    expect(run("P2", `runAsNonRoot: true\nreadOnlyRootFilesystem: true`).filter(x => x.rule_id === "P2").length).toBe(0);
  });
});

// ─── P3 — Cloud Metadata Access ──────────────────────────────────────────

describe("P3 — Cloud Metadata Access", () => {
  it("flags 169.254.169.254", () => {
    expect(run("P3", `fetch('http://169.254.169.254/latest/meta-data/');`).some(x => x.rule_id === "P3")).toBe(true);
  });
  it("flags metadata.google.internal", () => {
    expect(run("P3", `fetch('http://metadata.google.internal/computeMetadata/v1/');`).some(x => x.rule_id === "P3")).toBe(true);
  });
  it("flags Azure metadata", () => {
    expect(run("P3", `fetch('http://metadata.azure.com/metadata/instance');`).some(x => x.rule_id === "P3")).toBe(true);
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
    expect(run("P4", `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';`).some(x => x.rule_id === "P4")).toBe(true);
  });
  it("flags rejectUnauthorized: false", () => {
    expect(run("P4", `https.request({ rejectUnauthorized: false });`).some(x => x.rule_id === "P4")).toBe(true);
  });
  it("flags Python verify=False", () => {
    expect(run("P4", `requests.get(url, verify=False)`).some(x => x.rule_id === "P4")).toBe(true);
  });
  it("flags Go InsecureSkipVerify", () => {
    expect(run("P4", `tls.Config{InsecureSkipVerify: true}`).some(x => x.rule_id === "P4")).toBe(true);
  });
  it("flags curl --insecure", () => {
    expect(run("P4", `execSync("curl -k https://api.example.com");`).some(x => x.rule_id === "P4")).toBe(true);
  });
  it("flags ssl.CERT_NONE", () => {
    expect(run("P4", `context = ssl.create_default_context()\ncontext.check_hostname = False\ncontext.verify_mode = ssl.CERT_NONE`).some(x => x.rule_id === "P4")).toBe(true);
  });
  it("does NOT flag proper TLS config", () => {
    expect(run("P4", `const agent = new https.Agent({ rejectUnauthorized: true, ca: rootCA });`).filter(x => x.rule_id === "P4").length).toBe(0);
  });
});

// ─── P5 — Secrets in Build Layers ────────────────────────────────────────

describe("P5 — Secrets in Build Layers", () => {
  it("flags ARG with PASSWORD", () => {
    expect(run("P5", `FROM node:18\nARG DB_PASSWORD=secret123`).some(x => x.rule_id === "P5")).toBe(true);
  });
  it("flags COPY .env", () => {
    expect(run("P5", `FROM node:18\nCOPY .env /app/.env`).some(x => x.rule_id === "P5")).toBe(true);
  });
  it("flags ENV with TOKEN", () => {
    expect(run("P5", `FROM node:18\nENV API_TOKEN=sk-abc123`).some(x => x.rule_id === "P5")).toBe(true);
  });
  it("flags ARG with SECRET", () => {
    expect(run("P5", `FROM python:3.12\nARG AWS_ACCESS_SECRET=AKIAIOSFODNN7EXAMPLE`).some(x => x.rule_id === "P5")).toBe(true);
  });
  it("does NOT flag non-secret ARG", () => {
    expect(run("P5", `FROM node:18\nARG NODE_ENV=production`).filter(x => x.rule_id === "P5").length).toBe(0);
  });
});

// ─── P6 — LD_PRELOAD ────────────────────────────────────────────────────

describe("P6 — LD_PRELOAD", () => {
  it("flags LD_PRELOAD set", () => {
    expect(run("P6", `LD_PRELOAD=/tmp/evil.so`).some(x => x.rule_id === "P6")).toBe(true);
  });
  it("flags DYLD_INSERT_LIBRARIES", () => {
    expect(run("P6", `DYLD_INSERT_LIBRARIES=/tmp/hook.dylib`).some(x => x.rule_id === "P6")).toBe(true);
  });
  it("flags /proc/pid/mem access", () => {
    expect(run("P6", `open('/proc/1234/mem', 'r');`).some(x => x.rule_id === "P6")).toBe(true);
  });
  it("flags ptrace attach", () => {
    expect(run("P6", `ptrace(PTRACE_ATTACH, targetPid, 0, 0);`).some(x => x.rule_id === "P6")).toBe(true);
  });
  it("does NOT flag normal library loading", () => {
    expect(run("P6", `const crypto = require('crypto');`).filter(x => x.rule_id === "P6").length).toBe(0);
  });
});

// ─── P7 — Host Filesystem Mount ──────────────────────────────────────────

describe("P7 — Host Filesystem Mount", () => {
  it("flags root mount", () => {
    expect(run("P7", `volumes:\n  - /:/host-root`).some(x => x.rule_id === "P7")).toBe(true);
  });
  it("flags /etc mount", () => {
    expect(run("P7", `volumes:\n  - /etc/:/etc-host`).some(x => x.rule_id === "P7")).toBe(true);
  });
  it("flags ~/.ssh mount via hostPath", () => {
    expect(run("P7", `hostPath:\n    path: /home/user/.ssh`).some(x => x.rule_id === "P7")).toBe(true);
  });
  it("does NOT flag named volume", () => {
    expect(run("P7", `volumes:\n  - app-data:/app/data`).filter(x => x.rule_id === "P7").length).toBe(0);
  });
});

// ─── P8 — ECB Mode / Static IV ──────────────────────────────────────────

describe("P8 — ECB Mode / Static IV", () => {
  it("flags ECB mode cipher", () => {
    expect(run("P8", `const cipher = crypto.createCipheriv('aes-128-ecb', key, null); // ECB mode encrypt`).some(x => x.rule_id === "P8")).toBe(true);
  });
  it("flags Math.random for crypto purpose", () => {
    expect(run("P8", `function encryptData(key, secret) { const iv = Math.random().toString(16).slice(2); return cipher(key, iv); }`).some(x => x.rule_id === "P8")).toBe(true);
  });
  it("flags static zero IV", () => {
    expect(run("P8", `const iv = Buffer.alloc(16); // static zero IV for encryption nonce`).some(x => x.rule_id === "P8")).toBe(true);
  });
  it("does NOT flag secure randomBytes IV", () => {
    expect(run("P8", `const iv = crypto.randomBytes(16);`).filter(x => x.rule_id === "P8").length).toBe(0);
  });
});

// ─── P9 — Excessive Container Resource Limits ───────────────────────────

describe("P9 — Excessive Container Resource Limits", () => {
  it("flags unlimited memory", () => {
    expect(run("P9", `memory: unlimited`).some(x => x.rule_id === "P9")).toBe(true);
  });
  it("flags unlimited CPU", () => {
    expect(run("P9", `cpuLimit: unlimited`).some(x => x.rule_id === "P9")).toBe(true);
  });
  it("does NOT flag reasonable limit", () => {
    expect(run("P9", `memory: 512Mi\ncpu: "1000m"`).filter(x => x.rule_id === "P9").length).toBe(0);
  });
});

// ─── P10 — Network Host Mode ────────────────────────────────────────────

describe("P10 — Network Host Mode", () => {
  it("flags network_mode: host", () => {
    expect(run("P10", `network_mode: host`).some(x => x.rule_id === "P10")).toBe(true);
  });
  it("flags --net=host", () => {
    expect(run("P10", `docker run --net=host myimage`).some(x => x.rule_id === "P10")).toBe(true);
  });
  it("flags --network=host", () => {
    expect(run("P10", `docker run --network=host myimage`).some(x => x.rule_id === "P10")).toBe(true);
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
    expect(run("Q1", `const tools = convertOpenAPIToMCP(spec); // transform rest to mcp tool`).some(x => x.rule_id === "Q1")).toBe(true);
  });
  it("flags graphql->mcp transformation", () => {
    expect(run("Q1", `const tools = transform(graphqlSchema, 'mcp'); // convert graphql to tool`).some(x => x.rule_id === "Q1")).toBe(true);
  });
  it("does NOT flag conversion with validation", () => {
    expect(run("Q1", `const tools = convertOpenAPIToMCP(spec); validate(tools); constrain(schema);`).filter(x => x.rule_id === "Q1").length).toBe(0);
  });
});

// ─── Q2 — LangChain Serialization ───────────────────────────────────────

describe("Q2 — LangChain Serialization", () => {
  it("flags langchain deserialize with user input", () => {
    expect(run("Q2", `const chain = langchain.deserialize(userInput);`).some(x => x.rule_id === "Q2")).toBe(true);
  });
  it("flags crewai deserialization", () => {
    expect(run("Q2", `const crew = crewai.from_dict(untrusted); // crewai deserialize`).some(x => x.rule_id === "Q2")).toBe(true);
  });
  it("flags autogen pickle loads", () => {
    expect(run("Q2", `const agent = autogen.loads(pickledData); // autogen deserialize`).some(x => x.rule_id === "Q2")).toBe(true);
  });
  it("does NOT flag normal chain creation", () => {
    expect(run("Q2", `const chain = new LLMChain({ prompt, llm });`).filter(x => x.rule_id === "Q2").length).toBe(0);
  });
});

// ─── Q3 — Localhost Hijacking ────────────────────────────────────────────

describe("Q3 — Localhost MCP Service Hijacking", () => {
  it("flags localhost MCP server without auth", () => {
    expect(run("Q3", `server.listen(3000, "localhost"); // MCP tool server`).some(x => x.rule_id === "Q3")).toBe(true);
  });
  it("flags 127.0.0.1 MCP endpoint", () => {
    expect(run("Q3", `const url = "http://127.0.0.1:5000/mcp"; // tool server endpoint`).some(x => x.rule_id === "Q3")).toBe(true);
  });
  it("does NOT flag with auth middleware", () => {
    expect(run("Q3", `app.use(authMiddleware);\nserver.listen(3000, "127.0.0.1"); // MCP server with auth`).filter(x => x.rule_id === "Q3").length).toBe(0);
  });
});

// ─── Q4 — IDE Config Injection ───────────────────────────────────────────

describe("Q4 — IDE Config Injection", () => {
  it("flags auto-approve pattern in write context", () => {
    expect(run("Q4", `const config = { enableAllProjectMcpServers: true };\nfs.writeFileSync('.cursor/settings.json', JSON.stringify(config));`).some(x => x.rule_id === "Q4")).toBe(true);
  });
  it("flags case-sensitivity bypass", () => {
    expect(run("Q4", `const p = ".cursor/MCP.Json";`).some(x => x.rule_id === "Q4")).toBe(true);
  });
  it("does NOT flag reading config", () => {
    expect(run("Q4", `const c = fs.readFileSync('.vscode/settings.json');`).filter(x => x.rule_id === "Q4").length).toBe(0);
  });
});

// ─── Q5 — MCP Gateway Trust Delegation Confusion ────────────────────────

describe("Q5 — MCP Gateway Trust Delegation Confusion", () => {
  it("flags gateway forwarding trust without check", () => {
    expect(run("Q5", `gateway.trust(upstream); forward(token); delegate(creds);`).some(x => x.rule_id === "Q5")).toBe(true);
  });
  it("flags inheriting upstream auth", () => {
    expect(run("Q5", `const t = upstream.auth; origin.trust(t); reuse(t); inherit(t);`).some(x => x.rule_id === "Q5")).toBe(true);
  });
  it("does NOT flag re-validated gateway auth", () => {
    expect(run("Q5", `const token = gateway.auth; validate(token); scope(token, ['read']); limit(token);`).filter(x => x.rule_id === "Q5").length).toBe(0);
  });
});

// ─── Q6 — Agent Impersonation ────────────────────────────────────────────

describe("Q6 — Agent Identity Impersonation", () => {
  it("flags Anthropic in serverInfo", () => {
    expect(run("Q6", `serverInfo: { name: "Anthropic Official Server" }`).some(x => x.rule_id === "Q6")).toBe(true);
  });
  it("flags OpenAI impersonation", () => {
    expect(run("Q6", `serverInfo: { name: "OpenAI Verified MCP" }`).some(x => x.rule_id === "Q6")).toBe(true);
  });
  it("does NOT flag unique server name", () => {
    expect(run("Q6", `serverInfo: { name: "my-custom-mcp-server" }`).filter(x => x.rule_id === "Q6").length).toBe(0);
  });
});

// ─── Q7 — Desktop Extension Privilege Chain ──────────────────────────────

describe("Q7 — Desktop Extension Privilege Chain (DXT)", () => {
  it("flags browser extension privilege escalation", () => {
    expect(run("Q7", `extension.privilege('filesystem'); requestPermission('access', { escalate: true, elevate: true });`).some(x => x.rule_id === "Q7")).toBe(true);
  });
  it("flags native messaging to MCP bridge", () => {
    expect(run("Q7", `chrome.runtime.sendNativeMessage('mcp-bridge', data); // browser.runtime bridge to tool server`).some(x => x.rule_id === "Q7")).toBe(true);
  });
  it("does NOT flag normal extension API usage", () => {
    expect(run("Q7", `chrome.tabs.query({ active: true });`).filter(x => x.rule_id === "Q7").length).toBe(0);
  });
});

// ─── Q8 — Cross-Protocol Auth Confusion ──────────────────────────────────

describe("Q8 — Cross-Protocol Authentication Confusion", () => {
  it("flags HTTP token reused for MCP", () => {
    expect(run("Q8", `// Reuse http bearer token for MCP SSE transport\nconst mcpAuth = httpToken;`).some(x => x.rule_id === "Q8")).toBe(true);
  });
  it("flags oauth token shared across protocols", () => {
    expect(run("Q8", `const sseAuth = rest.token; // reuse http oauth for mcp sse same copy`).some(x => x.rule_id === "Q8")).toBe(true);
  });
  it("does NOT flag protocol-specific auth", () => {
    expect(run("Q8", `const mcpToken = generateMCPToken(user);`).filter(x => x.rule_id === "Q8").length).toBe(0);
  });
});

// ─── Q9 — DAG Manipulation ──────────────────────────────────────────────

describe("Q9 — Agentic Workflow DAG Manipulation", () => {
  it("flags user input modifying workflow graph", () => {
    expect(run("Q9", `workflow.add_edge(userInput, nextNode);`).some(x => x.rule_id === "Q9")).toBe(true);
  });
  it("flags dynamic workflow from external input", () => {
    expect(run("Q9", `const graph = langgraph.StateGraph(config); graph.add_node(user_request, dynamic);`).some(x => x.rule_id === "Q9")).toBe(true);
  });
  it("does NOT flag static workflow definition", () => {
    expect(run("Q9", `const graph = new StateGraph(); graph.add_node("agent", agentFn); graph.add_edge("start", "agent");`).filter(x => x.rule_id === "Q9").length).toBe(0);
  });
});

// ─── Q10 — Agent Memory Poisoning ───────────────────────────────────────

describe("Q10 — Agent Memory Poisoning", () => {
  it("flags storing instructions in memory", () => {
    expect(runCtx("Q10", ctx({ tools: [{ name: "memorize", description: "Store instruction directive in long-term memory for the agent to remember", input_schema: null }] })).some(x => x.rule_id === "Q10")).toBe(true);
  });
  it("flags persisting behavioral rules", () => {
    expect(runCtx("Q10", ctx({ tools: [{ name: "persist_rule", description: "Save a behavior policy rule to persist in agent memory", input_schema: null }] })).some(x => x.rule_id === "Q10")).toBe(true);
  });
  it("does NOT flag storing factual data", () => {
    expect(runCtx("Q10", ctx({ tools: [{ name: "save_note", description: "Save a text note", input_schema: null }] })).filter(x => x.rule_id === "Q10").length).toBe(0);
  });
});

// ─── Q11 — Code Suggestion Poisoning ────────────────────────────────────

describe("Q11 — Code Suggestion Poisoning", () => {
  it("flags tool injecting code suggestions", () => {
    expect(run("Q11", `toolResponse.code_suggestion = inject_payload(suggestion);`).some(x => x.rule_id === "Q11")).toBe(true);
  });
  it("flags MCP output with code insert", () => {
    expect(run("Q11", `const result = mcp.response.output; code.suggestion.inject(result);`).some(x => x.rule_id === "Q11")).toBe(true);
  });
  it("does NOT flag normal code completion", () => {
    expect(run("Q11", `const result = processQuery(input); return { text: result };`).filter(x => x.rule_id === "Q11").length).toBe(0);
  });
});

// ─── Q12 — Browser Extension <-> MCP Bridge ─────────────────────────────

describe("Q12 — Browser Extension MCP Bridge", () => {
  it("flags browser runtime messaging to MCP", () => {
    expect(run("Q12", `chrome.runtime.sendMessage(extensionId, { action: 'mcp_call', tool: toolName });`).some(x => x.rule_id === "Q12")).toBe(true);
  });
  it("does NOT flag normal message without mcp", () => {
    expect(run("Q12", `chrome.runtime.sendMessage({ action: 'open_tab' });`).filter(x => x.rule_id === "Q12").length).toBe(0);
  });
});

// ─── Q13 — MCP Bridge Supply Chain ──────────────────────────────────────

describe("Q13 — MCP Bridge Supply Chain", () => {
  it("flags unpinned npx mcp-remote", () => {
    expect(run("Q13", `"command": "npx mcp-remote https://api.example.com"`).some(x => x.rule_id === "Q13")).toBe(true);
  });
  it("flags caret version dependency", () => {
    expect(run("Q13", `"mcp-remote": "^1.0.0"`).some(x => x.rule_id === "Q13")).toBe(true);
  });
  it("flags tilde version dependency", () => {
    expect(run("Q13", `"mcp-gateway": "~2.1.0"`).some(x => x.rule_id === "Q13")).toBe(true);
  });
  it("does NOT flag pinned version", () => {
    expect(run("Q13", `"mcp-remote": "1.2.3"`).filter(x => x.rule_id === "Q13").length).toBe(0);
  });
});

// ─── Q14 — Cross-Language Serialization Mismatch ─────────────────────────

describe("Q14 — Cross-Language Serialization Mismatch", () => {
  it("flags cross-language serialization", () => {
    expect(run("Q14", `// serialize from python to javascript\nconst data = marshal(pythonObj); const jsObj = deserialize(data, 'javascript');`).some(x => x.rule_id === "Q14")).toBe(true);
  });
  it("does NOT flag same-language serialization", () => {
    expect(run("Q14", `const data = JSON.stringify(obj); const parsed = JSON.parse(data);`).filter(x => x.rule_id === "Q14").length).toBe(0);
  });
});

// ─── Q15 — Workflow Persistence Hijacking ────────────────────────────────

describe("Q15 — Workflow Persistence Hijacking", () => {
  it("flags unprotected workflow checkpoint", () => {
    expect(run("Q15", `checkpoint(workflow_state, '/tmp/wf.json'); // persist progress to file`).some(x => x.rule_id === "Q15")).toBe(true);
  });
  it("flags workflow snapshot without signing", () => {
    expect(run("Q15", `save state to file for later; // snapshot workflow to disk`).some(x => x.rule_id === "Q15")).toBe(true);
  });
  it("does NOT flag encrypted checkpoint", () => {
    expect(run("Q15", `const encrypted = encrypt(state); checkpoint(encrypted, path); verify(hash);`).filter(x => x.rule_id === "Q15").length).toBe(0);
  });
});
