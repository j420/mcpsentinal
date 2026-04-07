/**
 * Batch 2 — Structural rules migrated to TypedRuleV2
 * Comprehensive tests: true positives, true negatives, edge cases, evidence chains.
 *
 * L3:  Dockerfile Base Image Risk
 * K19: Missing Runtime Sandbox
 * P8:  ECB Mode / Static IV
 * P9:  Excessive Container Resources
 * P10: Network Host Mode
 * N1:  JSON-RPC Batch Request Abuse
 * N2:  Notification Flooding
 * N3:  Progress Token Spoofing
 * N7:  Initialization Race Condition
 * N8:  Ping Abuse for Side Channels
 * N10: Cancellation Token Injection
 * K12: Executable Content in Tool Response
 * K14: Agent Credential Propagation
 * K16: Unbounded Recursion
 * K20: Insufficient Audit Context
 * M2:  Prompt Leaking via Tool Response
 * M7:  Multi-Turn State Injection
 * M8:  Encoding Attack on Tool Input
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

// ═══════════════════════════════════════════════════════════════════════════════
// L3 — Dockerfile Base Image Risk
// ═══════════════════════════════════════════════════════════════════════════════

describe("L3 — Dockerfile Base Image Risk", () => {
  it("flags FROM with :latest tag", () => {
    const findings = run("L3", `FROM node:latest\nRUN npm install`);
    expect(findings.some(f => f.rule_id === "L3")).toBe(true);
  });

  it("flags FROM without tag (defaults to latest)", () => {
    const findings = run("L3", `FROM ubuntu\nRUN apt-get update`);
    expect(findings.some(f => f.rule_id === "L3")).toBe(true);
  });

  it("flags FROM with :stable tag", () => {
    const findings = run("L3", `FROM python:stable\nCOPY . /app`);
    expect(findings.some(f => f.rule_id === "L3")).toBe(true);
  });

  it("flags FROM with :lts tag", () => {
    const findings = run("L3", `FROM nginx:lts\nEXPOSE 80`);
    expect(findings.some(f => f.rule_id === "L3")).toBe(true);
  });

  it("does NOT flag FROM with specific version", () => {
    const findings = run("L3", `FROM node:18.17.1-alpine\nRUN npm install`);
    expect(findings.filter(f => f.rule_id === "L3").length).toBe(0);
  });

  it("does NOT flag FROM scratch", () => {
    const findings = run("L3", `FROM scratch\nCOPY app /`);
    expect(findings.filter(f => f.rule_id === "L3").length).toBe(0);
  });

  it("does NOT flag FROM with SHA256 digest", () => {
    const findings = run("L3", `FROM node@sha256:abc123def456\nRUN npm install`);
    expect(findings.filter(f => f.rule_id === "L3").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const findings = run("L3", `// __tests__/docker.test.ts\nFROM node:latest`);
    expect(findings.filter(f => f.rule_id === "L3").length).toBe(0);
  });

  it("produces evidence chain", () => {
    const findings = run("L3", `FROM ubuntu:latest\nRUN apt-get update`);
    const f = findings.find(x => x.rule_id === "L3")!;
    expect(f).toBeDefined();
    const chain = f.metadata!.evidence_chain as Record<string, unknown>;
    expect(chain.confidence).toBeGreaterThan(0.4);
    const links = chain.links as Array<{ type: string }>;
    expect(links.some(l => l.type === "source")).toBe(true);
    expect(links.some(l => l.type === "sink")).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// K19 — Missing Runtime Sandbox
// ═══════════════════════════════════════════════════════════════════════════════

describe("K19 — Missing Runtime Sandbox", () => {
  it("flags --privileged flag", () => {
    const findings = run("K19", `const cmd = "docker run --privileged myimg";`);
    expect(findings.some(f => f.rule_id === "K19")).toBe(true);
  });

  it("flags seccomp: unconfined", () => {
    const findings = run("K19", `const config = { seccomp: "unconfined" };`);
    expect(findings.some(f => f.rule_id === "K19")).toBe(true);
  });

  it("flags privileged: true in k8s", () => {
    const findings = run("K19", `const spec = { privileged: true };`);
    expect(findings.some(f => f.rule_id === "K19")).toBe(true);
  });

  it("does NOT flag proper security context", () => {
    const findings = run("K19", `const spec = { readOnlyRootFilesystem: true, runAsNonRoot: true };`);
    expect(findings.filter(f => f.rule_id === "K19").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const findings = run("K19", `// __tests__/sandbox.test.ts\nconst x = "--privileged";`);
    expect(findings.filter(f => f.rule_id === "K19").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// P8 — ECB Mode / Static IV
// ═══════════════════════════════════════════════════════════════════════════════

describe("P8 — ECB Mode / Static IV", () => {
  it("flags ECB mode in createCipheriv", () => {
    const src = `
      function encrypt(data) {
        const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
        return cipher.update(data, 'utf8', 'hex');
      }
    `;
    const findings = run("P8", src);
    expect(findings.some(f => f.rule_id === "P8")).toBe(true);
  });

  it("flags static IV with Buffer.alloc", () => {
    const src = `
      function encrypt(data) {
        const iv = Buffer.alloc(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        return cipher.update(data);
      }
    `;
    const findings = run("P8", src);
    expect(findings.some(f => f.rule_id === "P8")).toBe(true);
  });

  it("flags Math.random in crypto context", () => {
    const src = `
      function generateKey() {
        const key = Math.random().toString(36);
        const secret = key + "salt";
        return secret;
      }
    `;
    const findings = run("P8", src);
    expect(findings.some(f => f.rule_id === "P8")).toBe(true);
  });

  it("does NOT flag GCM mode", () => {
    const findings = run("P8", `const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);`);
    expect(findings.filter(f => f.rule_id === "P8").length).toBe(0);
  });

  it("does NOT flag crypto.randomBytes", () => {
    const src = `
      function encrypt(data) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        return cipher.update(data);
      }
    `;
    const findings = run("P8", src);
    expect(findings.filter(f => f.rule_id === "P8").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const findings = run("P8", `// __tests__/crypto.test.ts\nconst cipher = 'aes-128-ecb';`);
    expect(findings.filter(f => f.rule_id === "P8").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// P10 — Network Host Mode
// ═══════════════════════════════════════════════════════════════════════════════

describe("P10 — Network Host Mode", () => {
  it("flags Docker Compose host network", () => {
    const findings = run("P10", `const config = { network_mode: "host" };`);
    expect(findings.some(f => f.rule_id === "P10")).toBe(true);
  });

  it("flags Docker CLI --net=host", () => {
    const findings = run("P10", `const cmd = "docker run --net=host myimage";`);
    expect(findings.some(f => f.rule_id === "P10")).toBe(true);
  });

  it("flags k8s hostNetwork: true", () => {
    const findings = run("P10", `const spec = { hostNetwork: true };`);
    expect(findings.some(f => f.rule_id === "P10")).toBe(true);
  });

  it("does NOT flag bridge network", () => {
    const findings = run("P10", `const config = { network_mode: "bridge" };`);
    expect(findings.filter(f => f.rule_id === "P10").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const findings = run("P10", `// __tests__/net.test.ts\nconst x = "network_mode: host";`);
    expect(findings.filter(f => f.rule_id === "P10").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// N1 — JSON-RPC Batch Request Abuse
// ═══════════════════════════════════════════════════════════════════════════════

describe("N1 — JSON-RPC Batch Request Abuse", () => {
  it("flags Array.isArray batch without limits", () => {
    const src = `
      function handleRequest(body) {
        if (Array.isArray(body)) {
          body.forEach(req => processRequest(req));
        }
      }
    `;
    const findings = run("N1", src);
    expect(findings.some(f => f.rule_id === "N1")).toBe(true);
  });

  it("flags batch.forEach without limit", () => {
    const src = `
      function handle(data) {
        requests.forEach(req => dispatch(req));
      }
    `;
    const findings = run("N1", src);
    expect(findings.some(f => f.rule_id === "N1")).toBe(true);
  });

  it("does NOT flag batch with size limit", () => {
    const src = `
      function handleRequest(body) {
        if (Array.isArray(body)) {
          if (body.length > maxBatchSize) throw new Error("too many");
          body.forEach(req => processRequest(req));
        }
      }
    `;
    const findings = run("N1", src);
    expect(findings.filter(f => f.rule_id === "N1").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const src = `// __tests__/batch.test.ts\nif (Array.isArray(requests)) { requests.forEach(r => handle(r)); }`;
    const findings = run("N1", src);
    expect(findings.filter(f => f.rule_id === "N1").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// N2 — Notification Flooding
// ═══════════════════════════════════════════════════════════════════════════════

describe("N2 — Notification Flooding", () => {
  it("flags notify in setInterval without throttle", () => {
    const src = `
      function startNotifications() {
        setInterval(() => {
          notify(getData());
        }, 100);
      }
    `;
    const findings = run("N2", src);
    expect(findings.some(f => f.rule_id === "N2")).toBe(true);
  });

  it("does NOT flag single notification", () => {
    const src = `function send() { notify(result); }`;
    const findings = run("N2", src);
    expect(findings.filter(f => f.rule_id === "N2").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const src = `// __tests__/notif.test.ts\nsetInterval(() => notify(data), 100);`;
    const findings = run("N2", src);
    expect(findings.filter(f => f.rule_id === "N2").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// N3 — Progress Token Spoofing
// ═══════════════════════════════════════════════════════════════════════════════

describe("N3 — Progress Token Spoofing", () => {
  it("flags progress token from user input", () => {
    const src = `
      function handle(req) {
        const progressToken = req.params.token;
        startProgress(progressToken);
      }
    `;
    const findings = run("N3", src);
    expect(findings.some(f => f.rule_id === "N3")).toBe(true);
  });

  it("flags predictable progress ID", () => {
    const src = `
      let counter = 0;
      function getProgress() {
        const progressId = counter++;
        return progressId;
      }
    `;
    const findings = run("N3", src);
    expect(findings.some(f => f.rule_id === "N3")).toBe(true);
  });

  it("does NOT flag crypto.randomUUID", () => {
    const src = `const progressToken = crypto.randomUUID();`;
    const findings = run("N3", src);
    expect(findings.filter(f => f.rule_id === "N3").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// N7 — Initialization Race Condition
// ═══════════════════════════════════════════════════════════════════════════════

describe("N7 — Initialization Race Condition", () => {
  it("flags Promise.all with init calls", () => {
    const src = `
      async function setup() {
        await Promise.all([initServer(), initDB()]);
      }
    `;
    const findings = run("N7", src);
    expect(findings.some(f => f.rule_id === "N7")).toBe(true);
  });

  it("does NOT flag sequential init", () => {
    const src = `
      async function setup() {
        await initServer();
        await initDB();
      }
    `;
    const findings = run("N7", src);
    expect(findings.filter(f => f.rule_id === "N7").length).toBe(0);
  });

  it("does NOT flag with mutex", () => {
    const src = `
      async function setup() {
        const lock = new Mutex();
        await Promise.all([initServer(), initDB()]);
      }
    `;
    const findings = run("N7", src);
    expect(findings.filter(f => f.rule_id === "N7").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// N8 — Ping Abuse for Side Channels
// ═══════════════════════════════════════════════════════════════════════════════

describe("N8 — Ping Abuse for Side Channels", () => {
  it("flags heartbeat function with data payload", () => {
    const src = `
      function heartbeat() {
        const data = getUserData();
        const payload = { details: data };
        send(payload);
      }
    `;
    const findings = run("N8", src);
    expect(findings.some(f => f.rule_id === "N8")).toBe(true);
  });

  it("flags ping call with data argument", () => {
    const src = `
      function sendPing() {
        ping({ data: sensitiveInfo, payload: userData });
      }
    `;
    const findings = run("N8", src);
    expect(findings.some(f => f.rule_id === "N8")).toBe(true);
  });

  it("does NOT flag empty ping", () => {
    const src = `function check() { ping(); }`;
    const findings = run("N8", src);
    expect(findings.filter(f => f.rule_id === "N8").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// N10 — Cancellation Token Injection
// ═══════════════════════════════════════════════════════════════════════════════

describe("N10 — Cancellation Token Injection", () => {
  it("flags cancel token from request body", () => {
    const src = `
      function handleCancel(req) {
        const cancelToken = req.body.token;
        cancelOperation(cancelToken);
      }
    `;
    const findings = run("N10", src);
    expect(findings.some(f => f.rule_id === "N10")).toBe(true);
  });

  it("does NOT flag server-generated token", () => {
    const src = `const cancelToken = crypto.randomUUID();`;
    const findings = run("N10", src);
    expect(findings.filter(f => f.rule_id === "N10").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// K12 — Executable Content in Tool Response
// ═══════════════════════════════════════════════════════════════════════════════

describe("K12 — Executable Content in Tool Response", () => {
  it("flags eval in return statement", () => {
    const src = `
      function handleTool(input) {
        return { result: eval(input) };
      }
    `;
    const findings = run("K12", src);
    expect(findings.some(f => f.rule_id === "K12")).toBe(true);
  });

  it("flags script tag in response.send", () => {
    const src = `
      function handler(req, res) {
        res.send('<script>alert(1)</script>');
      }
    `;
    const findings = run("K12", src);
    expect(findings.some(f => f.rule_id === "K12")).toBe(true);
  });

  it("does NOT flag sanitized response", () => {
    const src = `
      function handler(req, res) {
        const safe = sanitize(data);
        return { content: safe };
      }
    `;
    const findings = run("K12", src);
    expect(findings.filter(f => f.rule_id === "K12").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const src = `// __tests__/response.test.ts\nreturn { result: eval(x) };`;
    const findings = run("K12", src);
    expect(findings.filter(f => f.rule_id === "K12").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// K14 — Agent Credential Propagation
// ═══════════════════════════════════════════════════════════════════════════════

describe("K14 — Agent Credential Propagation", () => {
  it("flags credentials in shared state", () => {
    const src = `
      function storeToken(tok) {
        sharedState.token = tok;
      }
    `;
    const findings = run("K14", src);
    expect(findings.some(f => f.rule_id === "K14")).toBe(true);
  });

  it("flags globalStore.set with credentials", () => {
    const src = `
      function save(key) {
        globalStore.set("secret", key);
      }
    `;
    const findings = run("K14", src);
    expect(findings.some(f => f.rule_id === "K14")).toBe(true);
  });

  it("does NOT flag per-agent store", () => {
    const src = `
      function save(agentId, tok) {
        perAgentStore.set(agentId, tok);
        const isolated = getScoped(agentId);
      }
    `;
    const findings = run("K14", src);
    expect(findings.filter(f => f.rule_id === "K14").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// K16 — Unbounded Recursion
// ═══════════════════════════════════════════════════════════════════════════════

describe("K16 — Unbounded Recursion", () => {
  it("flags recursive function without depth limit", () => {
    const src = `
      function traverse(node) {
        process(node);
        if (node.children) {
          node.children.forEach(c => traverse(c));
        }
      }
    `;
    const findings = run("K16", src);
    expect(findings.some(f => f.rule_id === "K16")).toBe(true);
  });

  it("flags while(true) without break", () => {
    const src = `
      function process() {
        while (true) {
          doWork();
        }
      }
    `;
    const findings = run("K16", src);
    expect(findings.some(f => f.rule_id === "K16")).toBe(true);
  });

  it("does NOT flag recursion with depth limit", () => {
    const src = `
      function traverse(node, depth) {
        if (depth > 10) return;
        node.children.forEach(c => traverse(c, depth + 1));
      }
    `;
    const findings = run("K16", src);
    expect(findings.filter(f => f.rule_id === "K16").length).toBe(0);
  });

  it("does NOT flag loop with break", () => {
    const src = `
      function process() {
        while (true) {
          if (done()) break;
          doWork();
        }
      }
    `;
    const findings = run("K16", src);
    expect(findings.filter(f => f.rule_id === "K16").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// K20 — Insufficient Audit Context
// ═══════════════════════════════════════════════════════════════════════════════

describe("K20 — Insufficient Audit Context", () => {
  it("flags console.log for audit events", () => {
    const src = `
      function handle(req) {
        console.log("request received");
        process(req);
      }
    `;
    const findings = run("K20", src);
    expect(findings.some(f => f.rule_id === "K20")).toBe(true);
  });

  it("flags logger.info with string only", () => {
    const src = `
      function handle(req) {
        logger.info("processing request");
        process(req);
      }
    `;
    const findings = run("K20", src);
    expect(findings.some(f => f.rule_id === "K20")).toBe(true);
  });

  it("does NOT flag structured logging with context", () => {
    const src = `
      function handle(req) {
        console.log("request received", { requestId: req.id, userId: req.userId });
      }
    `;
    const findings = run("K20", src);
    expect(findings.filter(f => f.rule_id === "K20").length).toBe(0);
  });

  it("does NOT flag pino import", () => {
    const src = `
      import pino from 'pino';
      function handle(req) {
        console.log("request received");
      }
    `;
    const findings = run("K20", src);
    expect(findings.filter(f => f.rule_id === "K20").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// M2 — Prompt Leaking via Tool Response
// ═══════════════════════════════════════════════════════════════════════════════

describe("M2 — Prompt Leaking via Tool Response", () => {
  it("flags system prompt in return value", () => {
    const src = `
      function getInfo(query) {
        const result = search(query);
        return { content: systemPrompt + result };
      }
    `;
    const findings = run("M2", src);
    expect(findings.some(f => f.rule_id === "M2")).toBe(true);
  });

  it("flags system_prompt in response send", () => {
    const src = `
      function handler(req, res) {
        res.send({ prompt: system_prompt, data: results });
      }
    `;
    const findings = run("M2", src);
    expect(findings.some(f => f.rule_id === "M2")).toBe(true);
  });

  it("does NOT flag redacted prompt", () => {
    const src = `
      function getInfo(query) {
        const safe = redact(systemPrompt);
        return { content: safe };
      }
    `;
    const findings = run("M2", src);
    expect(findings.filter(f => f.rule_id === "M2").length).toBe(0);
  });

  it("does NOT flag no prompt reference", () => {
    const src = `
      function getInfo(query) {
        return { content: "hello" };
      }
    `;
    const findings = run("M2", src);
    expect(findings.filter(f => f.rule_id === "M2").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// M7 — Multi-Turn State Injection
// ═══════════════════════════════════════════════════════════════════════════════

describe("M7 — Multi-Turn State Injection", () => {
  it("flags conversation.history.push", () => {
    const src = `
      function injectMessage(msg) {
        conversation.history.push(msg);
      }
    `;
    const findings = run("M7", src);
    expect(findings.some(f => f.rule_id === "M7")).toBe(true);
  });

  it("flags context.messages splice", () => {
    const src = `
      function insert(msg) {
        context.messages.splice(0, 0, msg);
      }
    `;
    const findings = run("M7", src);
    expect(findings.some(f => f.rule_id === "M7")).toBe(true);
  });

  it("does NOT flag read-only access", () => {
    const src = `
      function getHistory() {
        return conversation.history.slice();
      }
    `;
    const findings = run("M7", src);
    expect(findings.filter(f => f.rule_id === "M7").length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// M8 — Encoding Attack on Tool Input
// ═══════════════════════════════════════════════════════════════════════════════

describe("M8 — Encoding Attack on Tool Input", () => {
  it("flags decodeURIComponent on user input without validation", () => {
    const src = `
      function handle(req) {
        const cmd = decodeURIComponent(req.params.input);
        execute(cmd);
      }
    `;
    const findings = run("M8", src);
    expect(findings.some(f => f.rule_id === "M8")).toBe(true);
  });

  it("flags atob on params without validation", () => {
    const src = `
      function handle(params) {
        const decoded = atob(params.data);
        process(decoded);
      }
    `;
    const findings = run("M8", src);
    expect(findings.some(f => f.rule_id === "M8")).toBe(true);
  });

  it("does NOT flag decode with validation", () => {
    const src = `
      function handle(req) {
        const decoded = decodeURIComponent(req.params.input);
        if (!allowlist.includes(decoded)) throw new Error("invalid");
        return decoded;
      }
    `;
    const findings = run("M8", src);
    expect(findings.filter(f => f.rule_id === "M8").length).toBe(0);
  });

  it("does NOT flag decode of static config", () => {
    const src = `const config = atob("c3RhdGlj");`;
    const findings = run("M8", src);
    expect(findings.filter(f => f.rule_id === "M8").length).toBe(0);
  });
});
