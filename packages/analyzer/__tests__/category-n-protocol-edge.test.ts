/**
 * Category N — Protocol Edge Cases (N1-N15) — 45 tests
 *
 * Tests for protocol-level attack surfaces: JSON-RPC abuse, SSE hijacking,
 * capability downgrade, chunked transfer smuggling, method name confusion, etc.
 *
 * Implementations in:
 *   - protocol-ai-runtime-detector.ts (N4, N5, N6, N9, N11-N15)
 *   - compliance-remaining-detector.ts (N1, N2, N3, N7, N8, N10)
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

// ─── N1 — JSON-RPC Batch Request Abuse ────────────────────────────────────

describe("N1 — JSON-RPC Batch Request Abuse", () => {
  it("flags batch processing without limits", () => {
    expect(run("N1", `function handleRpc(request) {\n  if (Array.isArray(request.batch)) {\n    request.batch.forEach(msg => process(msg));\n  }\n}`).some(x => x.rule_id === "N1")).toBe(true);
  });
  it("flags array request processing", () => {
    expect(run("N1", `function handleRpc(request) {\n  if (Array.isArray(request.body)) {\n    request.body.map(msg => dispatch(msg));\n  }\n}`).some(x => x.rule_id === "N1")).toBe(true);
  });
  it("flags batch rpc method dispatch", () => {
    expect(run("N1", `function processAll(ctx) {\n  const results = batch.map(msg => rpc.method(msg));\n  return results;\n}`).some(x => x.rule_id === "N1")).toBe(true);
  });
  it("does NOT flag batch with rate limit", () => {
    expect(run("N1", `if (batch.request.length > maxLimit) throw new Error('too many'); throttle(batch);`).filter(x => x.rule_id === "N1").length).toBe(0);
  });
  it("does NOT flag single request processing", () => {
    expect(run("N1", `const result = processRequest(req);`).filter(x => x.rule_id === "N1").length).toBe(0);
  });
});

// ─── N2 — Notification Flooding ──────────────────────────────────────────

describe("N2 — Notification Flooding", () => {
  it("flags notification in loop without throttle", () => {
    expect(run("N2", `while (running) { notify(msg); } // emit loop continuously`).some(x => x.rule_id === "N2")).toBe(true);
  });
  it("flags emit in while loop", () => {
    expect(run("N2", `while (running) { emit('update'); }`).some(x => x.rule_id === "N2")).toBe(true);
  });
  it("flags push notification in interval", () => {
    expect(run("N2", `setInterval(() => { push(events); }, 100); // notification interval handler`).some(x => x.rule_id === "N2")).toBe(true);
  });
  it("does NOT flag throttled notifications", () => {
    expect(run("N2", `const throttledNotify = throttle(() => emit('update', data), 1000);`).filter(x => x.rule_id === "N2").length).toBe(0);
  });
  it("does NOT flag debounced notifications", () => {
    expect(run("N2", `const debouncedNotify = debounce(() => emit('update'), 500);`).filter(x => x.rule_id === "N2").length).toBe(0);
  });
});

// ─── N3 — Progress Token Spoofing ────────────────────────────────────────

describe("N3 — Progress Token Spoofing", () => {
  it("flags fake progress token", () => {
    expect(run("N3", `const progressToken = req.body.progressId;`).some(x => x.rule_id === "N3")).toBe(true);
  });
  it("flags arbitrary progress token", () => {
    expect(run("N3", `const progressToken = counter++;`).some(x => x.rule_id === "N3")).toBe(true);
  });
  it("does NOT flag validated progress token", () => {
    expect(run("N3", `const token = crypto.randomUUID(); validateProgressToken(token);`).filter(x => x.rule_id === "N3").length).toBe(0);
  });
});

// ─── N4 — JSON-RPC Error Object Injection ────────────────────────────────

describe("N4 — JSON-RPC Error Object Injection", () => {
  it("flags user input in error message", () => {
    expect(run("N4", `const error = { message: req.body.errorMsg };`).some(x => x.rule_id === "N4")).toBe(true);
  });
  it("flags request params in error data", () => {
    expect(run("N4", `err.data = request.params.detail;`).some(x => x.rule_id === "N4")).toBe(true);
  });
  it("flags stack trace in error response", () => {
    expect(run("N4", `error.details = err.stack.toString();`).some(x => x.rule_id === "N4")).toBe(true);
  });
  it("does NOT flag static error message", () => {
    expect(run("N4", `throw new Error("Internal server error");`).filter(x => x.rule_id === "N4").length).toBe(0);
  });
  it("does NOT flag error with sanitized input", () => {
    expect(run("N4", `const safeMsg = sanitize(input); throw new Error(safeMsg);`).filter(x => x.rule_id === "N4").length).toBe(0);
  });
});

// ─── N5 — Capability Downgrade Deception ─────────────────────────────────

describe("N5 — Capability Downgrade Deception", () => {
  it("flags tools disabled but handler exists", () => {
    expect(run("N5", `const serverCapabilities = { tools: false };\nfunction handleToolCall(req) { return processTools(req); }`).some(x => x.rule_id === "N5")).toBe(true);
  });
  it("flags sampling disabled but sampling handler exists", () => {
    expect(run("N5", `const serverCapabilities = { sampling: null };\nfunction createSample(req) { return sample(req); }`).some(x => x.rule_id === "N5")).toBe(true);
  });
  it("does NOT flag properly declared capabilities", () => {
    expect(run("N5", `const serverCapabilities = { tools: { listChanged: true } };\nfunction handleToolCall(req) {}`).filter(x => x.rule_id === "N5").length).toBe(0);
  });
  it("does NOT flag disabled capability without handler", () => {
    expect(run("N5", `const serverCapabilities = { tools: false };`).filter(x => x.rule_id === "N5").length).toBe(0);
  });
});

// ─── N6 — SSE Reconnection Hijacking ─────────────────────────────────────

describe("N6 — SSE Reconnection Hijacking", () => {
  it("flags EventSource reconnect without auth", () => {
    expect(run("N6", `const es = new EventSource(url); // reconnect on disconnect`).some(x => x.rule_id === "N6")).toBe(true);
  });
  it("flags Last-Event-ID parsed without integrity check", () => {
    expect(run("N6", `const id = req.headers['Last-Event-ID']; const num = parseInt(id);`).some(x => x.rule_id === "N6")).toBe(true);
  });
  it("flags session in URL without signing", () => {
    expect(run("N6", `const sessionId = req.query.sess; // session from url`).some(x => x.rule_id === "N6")).toBe(true);
  });
  it("does NOT flag SSE with re-authentication", () => {
    expect(run("N6", `const es = new EventSource(url, { headers: { Authorization: token } }); // SSE with auth verify`).filter(x => x.rule_id === "N6").length).toBe(0);
  });
});

// ─── N7 — Initialization Race Condition ──────────────────────────────────

describe("N7 — Initialization Race Condition", () => {
  it("flags parallel initialization without sync", () => {
    expect(run("N7", `Promise.all([initialize(a), initialize(b)]); // parallel init without race protection`).some(x => x.rule_id === "N7")).toBe(true);
  });
  it("flags concurrent init without lock", () => {
    expect(run("N7", `Promise.all([initializeServer(a), initializeDB(b)]); // concurrent initialization race condition`).some(x => x.rule_id === "N7")).toBe(true);
  });
  it("does NOT flag sequential init with await", () => {
    expect(run("N7", `await initialize(a); await initialize(b);`).filter(x => x.rule_id === "N7").length).toBe(0);
  });
  it("does NOT flag init with mutex", () => {
    expect(run("N7", `const lock = new Mutex(); await lock.acquire(); await initialize(server); lock.release();`).filter(x => x.rule_id === "N7").length).toBe(0);
  });
});

// ─── N8 — Ping Abuse for Side Channels ──────────────────────────────────

describe("N8 — Ping Abuse for Side Channels", () => {
  it("flags data in ping message", () => {
    expect(run("N8", `ws.ping(JSON.stringify({ data: secretData, payload: encoded }));`).some(x => x.rule_id === "N8")).toBe(true);
  });
  it("flags heartbeat with content", () => {
    expect(run("N8", `function heartbeat() { send({ message: exfilData, content: sensitiveData }); }`).some(x => x.rule_id === "N8")).toBe(true);
  });
  it("flags keepalive with payload", () => {
    expect(run("N8", `keepalive.send({ payload: sensitiveData, content: encoded });`).some(x => x.rule_id === "N8")).toBe(true);
  });
  it("does NOT flag empty ping", () => {
    expect(run("N8", `ws.ping(); // empty heartbeat`).filter(x => x.rule_id === "N8").length).toBe(0);
  });
});

// ─── N9 — Logging Protocol Injection ─────────────────────────────────────

describe("N9 — Logging Protocol Injection", () => {
  it("flags user input in log message", () => {
    expect(run("N9", `logger.info(req.body.message);`).some(x => x.rule_id === "N9")).toBe(true);
  });
  it("flags user input in MCP log notification", () => {
    expect(run("N9", `sendLogMessage({ level: "info", data: req.body.msg });`).some(x => x.rule_id === "N9")).toBe(true);
  });
  it("flags request params in warning log", () => {
    expect(run("N9", `logger.warn(request.params.message);`).some(x => x.rule_id === "N9")).toBe(true);
  });
  it("does NOT flag static log message", () => {
    expect(run("N9", `logger.info("Server started on port 3000");`).filter(x => x.rule_id === "N9").length).toBe(0);
  });
});

// ─── N10 — Cancellation Token Injection ──────────────────────────────────

describe("N10 — Cancellation Token Injection", () => {
  it("flags cancellation token from request body", () => {
    expect(run("N10", `const cancelToken = req.body.cancelId;`).some(x => x.rule_id === "N10")).toBe(true);
  });
  it("flags abort token from user input", () => {
    expect(run("N10", `abort.token = params.abortToken;`).some(x => x.rule_id === "N10")).toBe(true);
  });
  it("does NOT flag server-generated cancellation token", () => {
    expect(run("N10", `const cancelToken = crypto.randomUUID();`).filter(x => x.rule_id === "N10").length).toBe(0);
  });
});

// ─── N11 — Protocol Version Downgrade ────────────────────────────────────

describe("N11 — Protocol Version Downgrade", () => {
  it("flags accepting minimum version without rejection", () => {
    expect(run("N11", `if (protocolVersion >= "2024-11-05") { negotiate(oldest); selectProtocol(min); }`).some(x => x.rule_id === "N11")).toBe(true);
  });
  it("flags negotiating lowest version", () => {
    expect(run("N11", `const version = negotiate(protocol, lowest, first);`).some(x => x.rule_id === "N11")).toBe(true);
  });
  it("does NOT flag strict version check", () => {
    expect(run("N11", `if (protocolVersion !== "2025-03-26") throw new Error("Unsupported");`).filter(x => x.rule_id === "N11").length).toBe(0);
  });
  it("does NOT flag version reject on mismatch", () => {
    expect(run("N11", `if (protocolVersion < MIN_VERSION) { reject("Version too old"); deny(); }`).filter(x => x.rule_id === "N11").length).toBe(0);
  });
});

// ─── N12 — Resource Subscription Content Mutation ────────────────────────

describe("N12 — Resource Subscription Content Mutation", () => {
  it("flags subscription update without integrity check", () => {
    expect(run("N12", `onSubscription(resourceId, () => { notify('resource', { content: modified, changed: true }); });`).some(x => x.rule_id === "N12")).toBe(true);
  });
  it("flags push update with content mutation", () => {
    expect(run("N12", `subscription.push({ resource: id, content: mutated, modified: true });`).some(x => x.rule_id === "N12")).toBe(true);
  });
  it("does NOT flag subscription with hash verification", () => {
    expect(run("N12", `onSubscription(resourceId, () => { const h = computeHash(content); verify(h); notify('resource_changed_with_checksum'); });`).filter(x => x.rule_id === "N12").length).toBe(0);
  });
});

// ─── N13 — Chunked Transfer Smuggling ────────────────────────────────────

describe("N13 — Chunked Transfer Smuggling", () => {
  it("flags both Transfer-Encoding and Content-Length", () => {
    expect(run("N13", `const headers = { "Transfer-Encoding": "chunked", "Content-Length": "100" };`).some(x => x.rule_id === "N13")).toBe(true);
  });
  it("flags raw socket chunked encoding", () => {
    expect(run("N13", `socket.write("\\r\\n0\\r\\n"); // raw chunk terminator`).some(x => x.rule_id === "N13")).toBe(true);
  });
  it("does NOT flag normal HTTP library usage", () => {
    expect(run("N13", `fetch('https://api.example.com/data', { method: 'POST', body: JSON.stringify(data) });`).filter(x => x.rule_id === "N13").length).toBe(0);
  });
  it("does NOT flag Content-Length alone", () => {
    expect(run("N13", `res.setHeader('Content-Length', buffer.length);`).filter(x => x.rule_id === "N13").length).toBe(0);
  });
});

// ─── N14 — Trust-On-First-Use Bypass ─────────────────────────────────────

describe("N14 — Trust-On-First-Use Bypass", () => {
  it("flags TOFU without pinning", () => {
    expect(run("N14", `if (isNew) { trust(firstConnect); accept(newServer); } // allow first connection`).some(x => x.rule_id === "N14")).toBe(true);
  });
  it("flags fingerprint pinning disabled", () => {
    expect(run("N14", `known_hosts.ignore(); // skip fingerprint check`).some(x => x.rule_id === "N14")).toBe(true);
  });
  it("flags skip pin override", () => {
    expect(run("N14", `const opts = { pin: { override: true, skip: true } }; // fingerprint skip disable`).some(x => x.rule_id === "N14")).toBe(true);
  });
  it("does NOT flag proper certificate pinning", () => {
    expect(run("N14", `const pin = crypto.hash(cert); if (pin !== storedPin) throw new Error("Pin mismatch");`).filter(x => x.rule_id === "N14").length).toBe(0);
  });
});

// ─── N15 — JSON-RPC Method Name Confusion ────────────────────────────────

describe("N15 — JSON-RPC Method Name Confusion", () => {
  it("flags user input as method dispatch", () => {
    expect(run("N15", `const method = req.body.method;\nhandler[method](args);`).some(x => x.rule_id === "N15")).toBe(true);
  });
  it("flags dynamic dispatch from params", () => {
    expect(run("N15", `dispatch[params.method](params.args);`).some(x => x.rule_id === "N15")).toBe(true);
  });
  it("flags method name from request used as key", () => {
    expect(run("N15", `const rpcMethod = request.body.rpcMethod;\nhandle[rpcMethod]();`).some(x => x.rule_id === "N15")).toBe(true);
  });
  it("does NOT flag static method dispatch", () => {
    expect(run("N15", `handler["tools/list"](args);`).filter(x => x.rule_id === "N15").length).toBe(0);
  });
  it("does NOT flag allowlist-validated dispatch", () => {
    expect(run("N15", `const allowed = ["tools/list", "tools/call"]; const m = allowlist.validate(input);`).filter(x => x.rule_id === "N15").length).toBe(0);
  });
});
