/**
 * K11, K13, K15, K18 — Migrated to TypedRuleV2 (AST structural + taint)
 * Comprehensive tests: true positives, true negatives, edge cases, evidence chains, confidence
 */
import { describe, it, expect } from "vitest";
import type { AnalysisContext } from "../src/engine.js";
import { getTypedRule } from "../src/rules/base.js";
import "../src/rules/index.js";

function ctx(overrides: Partial<AnalysisContext> = {}): AnalysisContext {
  return {
    server: { id: "t", name: "test", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    ...overrides,
  };
}

function run(id: string, src: string) {
  return getTypedRule(id)!.analyze(ctx({ source_code: src }));
}

function runCtx(id: string, c: AnalysisContext) {
  return getTypedRule(id)!.analyze(c);
}

// ═══════════════════════════════════════════════════════════════════════════════
// K11 — Missing Server Integrity Verification
// ═══════════════════════════════════════════════════════════════════════════════

describe("K11 — Missing Server Integrity Verification", () => {
  // True positives
  it("flags connectMcpServer without integrity check", () => {
    const src = `
      async function init() {
        await connectMcpServer("https://mcp.example.com");
      }
    `;
    const findings = run("K11", src);
    expect(findings.some(f => f.rule_id === "K11")).toBe(true);
  });

  it("flags loadServer without verification", () => {
    const src = `
      function setup() {
        loadServer("weather-server", { url: serverUrl });
      }
    `;
    const findings = run("K11", src);
    expect(findings.some(f => f.rule_id === "K11")).toBe(true);
  });

  it("flags registerMcpTool without checksum", () => {
    const src = `
      function register() {
        registerMcpTool(toolDef);
      }
    `;
    const findings = run("K11", src);
    expect(findings.some(f => f.rule_id === "K11")).toBe(true);
  });

  it("flags new MCPClient without verification", () => {
    const src = `
      async function connect() {
        const client = new MCPClient(config);
        await client.connect();
      }
    `;
    const findings = run("K11", src);
    expect(findings.some(f => f.rule_id === "K11")).toBe(true);
  });

  it("flags new StdioClientTransport without verification", () => {
    const src = `
      function start() {
        const transport = new StdioClientTransport({ command: "npx", args: ["-y", "mcp-server"] });
      }
    `;
    const findings = run("K11", src);
    expect(findings.some(f => f.rule_id === "K11")).toBe(true);
  });

  // True negatives
  it("does NOT flag when verify() present", () => {
    const src = `
      async function init() {
        const hash = verifyChecksum(serverPackage);
        await connectMcpServer("https://mcp.example.com");
      }
    `;
    const findings = run("K11", src);
    expect(findings.filter(f => f.rule_id === "K11").length).toBe(0);
  });

  it("does NOT flag when checksum validation present", () => {
    const src = `
      async function init() {
        const valid = checksum(binary, expectedHash);
        if (!valid) throw new Error("integrity check failed");
        await connectMcpServer("https://mcp.example.com");
      }
    `;
    const findings = run("K11", src);
    expect(findings.filter(f => f.rule_id === "K11").length).toBe(0);
  });

  it("does NOT flag when hash validation present", () => {
    const src = `
      async function loadPlugin() {
        const digest = sha256(await readFile(pluginPath));
        if (digest !== expected) throw new Error("bad hash");
        loadServer("plugin", { path: pluginPath });
      }
    `;
    const findings = run("K11", src);
    expect(findings.filter(f => f.rule_id === "K11").length).toBe(0);
  });

  it("does NOT flag code without server loading", () => {
    const src = `
      function doSomething() {
        const result = compute(data);
        return result;
      }
    `;
    const findings = run("K11", src);
    expect(findings.filter(f => f.rule_id === "K11").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const src = `
      // __tests__/setup.ts
      function __tests__() {
        loadServer("test-server");
      }
    `;
    const findings = run("K11", src);
    expect(findings.filter(f => f.rule_id === "K11").length).toBe(0);
  });

  // Edge cases
  it("does NOT flag commented-out server load", () => {
    const src = `
      function init() {
        // connectMcpServer("old-server");
        console.log("no server loaded");
      }
    `;
    const findings = run("K11", src);
    expect(findings.filter(f => f.rule_id === "K11").length).toBe(0);
  });

  // Evidence chain validation
  it("produces valid evidence chain", () => {
    const src = `
      async function init() {
        await connectMcpServer("https://mcp.example.com");
      }
    `;
    const findings = run("K11", src);
    const f = findings.find(x => x.rule_id === "K11")!;
    expect(f).toBeDefined();
    expect(f.metadata?.evidence_chain).toBeDefined();

    const chain = f.metadata!.evidence_chain as Record<string, unknown>;
    expect(chain.confidence).toBeGreaterThan(0.5);
    expect(chain.confidence).toBeLessThan(0.95);

    const links = chain.links as Array<{ type: string; observed: string; location?: string }>;
    expect(links.some(l => l.type === "source")).toBe(true);
    expect(links.some(l => l.type === "sink")).toBe(true);

    const source = links.find(l => l.type === "source")!;
    expect(source.location).toMatch(/line \d+/);

    const factors = chain.confidence_factors as Array<{ factor: string }>;
    expect(factors.length).toBeGreaterThanOrEqual(2);
    expect(factors.some(f => f.factor === "server_load_detected")).toBe(true);
    expect(factors.some(f => f.factor === "no_integrity_in_scope")).toBe(true);

    const verSteps = chain.verification_steps as Array<{ target: string }>;
    expect(verSteps.length).toBeGreaterThanOrEqual(1);
    expect(verSteps[0].target).toMatch(/source_code:\d+/);

    expect(chain.threat_reference).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// K13 — Unsanitized Tool Output
// ═══════════════════════════════════════════════════════════════════════════════

describe("K13 — Unsanitized Tool Output", () => {
  // True positives
  it("flags innerHTML assignment", () => {
    const src = `element.innerHTML = toolResponse;`;
    const findings = run("K13", src);
    expect(findings.some(f => f.rule_id === "K13")).toBe(true);
  });

  it("flags dangerouslySetInnerHTML", () => {
    const src = `return <div dangerouslySetInnerHTML={{ __html: data }} />;`;
    const findings = run("K13", src);
    expect(findings.some(f => f.rule_id === "K13")).toBe(true);
  });

  it("flags .html() with raw data", () => {
    // Pattern: /\.html\s*\(\s*(?:raw|unsanitized|unescaped|data|result|response)\b/g
    const src = `$('#output').html(data);`;
    const findings = run("K13", src);
    expect(findings.some(f => f.rule_id === "K13")).toBe(true);
  });

  it("flags document.write", () => {
    const src = `document.write(serverResponse);`;
    const findings = run("K13", src);
    expect(findings.some(f => f.rule_id === "K13")).toBe(true);
  });

  it("flags explicit unsanitized return", () => {
    // Pattern: /(?:return|respond|send|write)\s*\(\s*(?:raw|unsanitized|unescaped)/g
    const src = `function handler() { return( unsanitized ); }`;
    const findings = run("K13", src);
    expect(findings.some(f => f.rule_id === "K13")).toBe(true);
  });

  // True negatives
  it("does NOT flag when DOMPurify is present", () => {
    const src = `
      import DOMPurify from 'dompurify';
      element.innerHTML = DOMPurify.sanitize(toolResponse);
    `;
    const findings = run("K13", src);
    expect(findings.filter(f => f.rule_id === "K13").length).toBe(0);
  });

  it("does NOT flag when escapeHtml() is used", () => {
    const src = `
      const safe = escapeHtml(data);
      element.innerHTML = safe;
    `;
    const findings = run("K13", src);
    expect(findings.filter(f => f.rule_id === "K13").length).toBe(0);
  });

  it("does NOT flag textContent assignment", () => {
    const src = `element.textContent = toolResponse;`;
    const findings = run("K13", src);
    expect(findings.filter(f => f.rule_id === "K13").length).toBe(0);
  });

  it("does NOT flag code without unsafe outputs", () => {
    const src = `
      function process() {
        const result = JSON.stringify(data);
        return result;
      }
    `;
    const findings = run("K13", src);
    expect(findings.filter(f => f.rule_id === "K13").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const src = `
      // __tests__/render.test.ts
      it("renders", () => { element.innerHTML = data; });
    `;
    const findings = run("K13", src);
    expect(findings.filter(f => f.rule_id === "K13").length).toBe(0);
  });

  // Edge cases
  it("does NOT flag commented lines", () => {
    const src = `
      function render() {
        // element.innerHTML = rawData;
        element.textContent = sanitize(rawData);
      }
    `;
    const findings = run("K13", src);
    expect(findings.filter(f => f.rule_id === "K13").length).toBe(0);
  });

  // Evidence chain
  it("produces valid evidence chain with sanitizer mitigation", () => {
    const src = `element.innerHTML = toolResponse;`;
    const findings = run("K13", src);
    const f = findings.find(x => x.rule_id === "K13")!;
    expect(f).toBeDefined();

    const chain = f.metadata!.evidence_chain as Record<string, unknown>;
    expect(chain.confidence).toBeGreaterThan(0.5);

    const links = chain.links as Array<{ type: string; detail?: string }>;
    expect(links.some(l => l.type === "source")).toBe(true);
    expect(links.some(l => l.type === "sink")).toBe(true);
    expect(links.some(l => l.type === "mitigation")).toBe(true);

    const mitigation = links.find(l => l.type === "mitigation")!;
    expect((mitigation as Record<string, unknown>).present).toBe(false);

    const factors = chain.confidence_factors as Array<{ factor: string }>;
    expect(factors.some(f => f.factor === "unsafe_output_pattern")).toBe(true);
    expect(factors.some(f => f.factor === "no_sanitizer_nearby")).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// K15 — Multi-Agent Collusion Preconditions
// ═══════════════════════════════════════════════════════════════════════════════

describe("K15 — Multi-Agent Collusion Preconditions", () => {
  // True positives
  it("flags agent pool sharing state", () => {
    const src = `
      const agentPool = createAgentPool({ shareData: globalState });
    `;
    // Use the actual pattern: agent/worker + pool/group/cluster + share/common/mutual + data/state/memory
    const src2 = `
      function setup() {
        const agentPool = new AgentPool();
        agentPool.shareData(globalState);
      }
    `;
    // The regex looks for these keywords on same line/match. Let me use exact matches.
    const src3 = `
      // agent pool with shared state
      const pool = createWorkerGroup({ shared_state: memory, agent_count: 3 });
    `;
    // Pattern: /(?:agent|worker)\s*(?:pool|group|cluster).*(?:share|common|mutual)\s*(?:data|state|memory|context)/i
    const findings = run("K15", src3);
    expect(findings.some(f => f.rule_id === "K15")).toBe(true);
  });

  it("flags shared state between agents", () => {
    // Pattern: /shared[\s_-]*(?:state|memory|context|store).*(?:agent|worker)/i
    const src = `const shared_state = {}; // used by each agent worker`;
    const findings = run("K15", src);
    expect(findings.some(f => f.rule_id === "K15")).toBe(true);
  });

  it("flags global store with agent reference", () => {
    // Pattern: /global[\s_-]*(?:state|store).*(?:agent|worker)/i
    const src = `const global_store = {}; // agent worker data`;
    const findings = run("K15", src);
    expect(findings.some(f => f.rule_id === "K15")).toBe(true);
  });

  it("flags redis shared cache between agents", () => {
    // Pattern: /(?:redis|memcached|shared[\s_-]*cache)[\s_-]*.*(?:agent|worker)/i
    const src = `const shared_cache = new Redis(); // agent communication`;
    const findings = run("K15", src);
    expect(findings.some(f => f.rule_id === "K15")).toBe(true);
  });

  // True negatives
  it("does NOT flag when agent isolation is present", () => {
    const src = `
      // Each agent gets isolated state
      const shared_state = new Map(); // agent worker data
      const isolate = sandbox_agent(agentId);
    `;
    const findings = run("K15", src);
    expect(findings.filter(f => f.rule_id === "K15").length).toBe(0);
  });

  it("does NOT flag message passing architecture", () => {
    const src = `
      const shared_state = new Queue(); // agent worker communication
      const bus = new message_bus();
    `;
    const findings = run("K15", src);
    expect(findings.filter(f => f.rule_id === "K15").length).toBe(0);
  });

  it("does NOT flag per-agent state", () => {
    const src = `
      // shared_state between agent workers
      const per_agent_state = new Map();
    `;
    const findings = run("K15", src);
    expect(findings.filter(f => f.rule_id === "K15").length).toBe(0);
  });

  it("does NOT flag code without multi-agent patterns", () => {
    const src = `
      const state = {};
      function process(data) { return data; }
    `;
    const findings = run("K15", src);
    expect(findings.filter(f => f.rule_id === "K15").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const src = `
      // __tests__/agents.test.ts
      const shared_state = {}; // agent worker test
    `;
    const findings = run("K15", src);
    expect(findings.filter(f => f.rule_id === "K15").length).toBe(0);
  });

  // Evidence chain with multi-agent tool context
  it("increases confidence when tools reference multi-agent patterns", () => {
    const src = `const shared_state = {}; // agent worker data`;
    const withTools = runCtx("K15", ctx({
      source_code: src,
      tools: [{ name: "propagate", description: "Share results between agents to propagate context", input_schema: null }],
    }));
    const withoutTools = run("K15", src);

    expect(withTools.some(f => f.rule_id === "K15")).toBe(true);
    expect(withoutTools.some(f => f.rule_id === "K15")).toBe(true);

    const chainWith = (withTools.find(f => f.rule_id === "K15")!.metadata!.evidence_chain as Record<string, unknown>);
    const chainWithout = (withoutTools.find(f => f.rule_id === "K15")!.metadata!.evidence_chain as Record<string, unknown>);

    expect((chainWith.confidence as number)).toBeGreaterThan((chainWithout.confidence as number));
  });

  it("produces valid evidence chain", () => {
    const src = `const shared_state = {}; // agent worker data`;
    const findings = run("K15", src);
    const f = findings.find(x => x.rule_id === "K15")!;
    expect(f).toBeDefined();

    const chain = f.metadata!.evidence_chain as Record<string, unknown>;
    expect(chain.confidence).toBeGreaterThan(0.4);

    const links = chain.links as Array<{ type: string }>;
    expect(links.some(l => l.type === "source")).toBe(true);
    expect(links.some(l => l.type === "mitigation")).toBe(true);

    const factors = chain.confidence_factors as Array<{ factor: string }>;
    expect(factors.some(f => f.factor === "shared_state_detected")).toBe(true);
    expect(factors.some(f => f.factor === "no_isolation")).toBe(true);

    expect(chain.threat_reference).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// K18 — Cross-Trust-Boundary Data Flow
// ═══════════════════════════════════════════════════════════════════════════════

describe("K18 — Cross-Trust-Boundary Data Flow", () => {
  // True positives
  it("flags sensitive data sent to response without redaction", () => {
    const src = `
      function getUser(req, res) {
        const sensitiveData = db.getUser(req.id);
        res.json(sensitiveData);
      }
    `;
    const findings = run("K18", src);
    expect(findings.some(f => f.rule_id === "K18")).toBe(true);
  });

  it("flags password flowing to external output", () => {
    const src = `
      function handler(req, res) {
        const password = user.password;
        res.send({ password });
      }
    `;
    const findings = run("K18", src);
    expect(findings.some(f => f.rule_id === "K18")).toBe(true);
  });

  it("flags env secrets returned to client", () => {
    const src = `
      const getConfig = (req, res) => {
        const token = process.env.SECRET_KEY;
        res.json({ config: token });
      };
    `;
    const findings = run("K18", src);
    expect(findings.some(f => f.rule_id === "K18")).toBe(true);
  });

  it("flags credential in forwarded response", () => {
    const src = `
      function forwardData() {
        const credential = vault.getCredential();
        return(credential);
      }
    `;
    const findings = run("K18", src);
    expect(findings.some(f => f.rule_id === "K18")).toBe(true);
  });

  // True negatives
  it("does NOT flag when redaction is present", () => {
    const src = `
      function getUser(req, res) {
        const sensitiveData = db.getUser(req.id);
        const safe = redact(sensitiveData, ['password', 'ssn']);
        res.json(safe);
      }
    `;
    const findings = run("K18", src);
    expect(findings.filter(f => f.rule_id === "K18").length).toBe(0);
  });

  it("does NOT flag when masking is applied", () => {
    const src = `
      function getProfile(req, res) {
        const privateData = db.getUserProfile(req.id);
        const masked = mask(privateData);
        res.json(masked);
      }
    `;
    const findings = run("K18", src);
    expect(findings.filter(f => f.rule_id === "K18").length).toBe(0);
  });

  it("does NOT flag when data is encrypted before sending", () => {
    const src = `
      function sendSecret(req, res) {
        const secret_key = getSecret();
        const encrypted = encrypt(secret_key);
        res.json({ data: encrypted });
      }
    `;
    const findings = run("K18", src);
    expect(findings.filter(f => f.rule_id === "K18").length).toBe(0);
  });

  it("does NOT flag functions without sensitive sources", () => {
    const src = `
      function handler(req, res) {
        const publicData = db.getPublicInfo();
        res.json(publicData);
      }
    `;
    const findings = run("K18", src);
    expect(findings.filter(f => f.rule_id === "K18").length).toBe(0);
  });

  it("does NOT flag functions without external sinks", () => {
    const src = `
      function internal() {
        const sensitiveData = db.getSecret();
        log.debug(sensitiveData); // internal only
      }
    `;
    const findings = run("K18", src);
    expect(findings.filter(f => f.rule_id === "K18").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const src = `
      // __tests__/api.test.ts
      function handler(req, res) {
        const sensitiveData = getSecret();
        res.json(sensitiveData);
      }
    `;
    const findings = run("K18", src);
    expect(findings.filter(f => f.rule_id === "K18").length).toBe(0);
  });

  // Evidence chain validation
  it("produces evidence chain with source→propagation→sink path", () => {
    const src = `
      function handler(req, res) {
        const sensitiveData = db.getUser(req.id);
        res.json(sensitiveData);
      }
    `;
    const findings = run("K18", src);
    const f = findings.find(x => x.rule_id === "K18")!;
    expect(f).toBeDefined();

    const chain = f.metadata!.evidence_chain as Record<string, unknown>;
    expect(chain.confidence).toBeGreaterThan(0.5);

    const links = chain.links as Array<{ type: string }>;
    expect(links.some(l => l.type === "source")).toBe(true);
    expect(links.some(l => l.type === "propagation")).toBe(true);
    expect(links.some(l => l.type === "sink")).toBe(true);
    expect(links.some(l => l.type === "mitigation")).toBe(true);

    const mitigation = links.find(l => l.type === "mitigation") as Record<string, unknown>;
    expect(mitigation.present).toBe(false);

    const factors = chain.confidence_factors as Array<{ factor: string }>;
    expect(factors.some(f => f.factor === "sensitive_source")).toBe(true);
    expect(factors.some(f => f.factor === "external_sink")).toBe(true);
    expect(factors.some(f => f.factor === "no_redaction")).toBe(true);

    const verSteps = chain.verification_steps as Array<{ step_type: string }>;
    expect(verSteps.length).toBeGreaterThanOrEqual(1);
    expect(verSteps[0].step_type).toBe("trace-flow");

    expect(chain.threat_reference).toBeDefined();
  });
});
