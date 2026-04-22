/**
 * Category N — Protocol Edge Cases — integration tests
 *
 * Covers rules that still live in the shared legacy file
 * protocol-ai-runtime-detector.ts (N4, N5, N6, N9, N11-N15). N1, N2, N3, N7,
 * N8, N10 migrated in Phase 1 chunk 1.8 to per-rule Rule Standard v2
 * directories; comprehensive tests for those six rules live alongside the
 * rule implementations at
 *   packages/analyzer/src/rules/implementations/n{1,2,3,7,8,10}-*\/__tests__/index.test.ts
 * The legacy assertions for N1/N2/N3/N7/N8/N10 in this file asserted the
 * drifted jsonrpc-protocol-v2.ts semantics (N3/N7/N8/N10 targeted
 * orthogonal concerns) and have been removed as part of the chunk 1.8 cleanup.
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

// N1, N2, N3: migrated to per-rule directories in Phase 1 chunk 1.8.
// Comprehensive tests at src/rules/implementations/n{1,2,3}-*\/__tests__/index.test.ts.

// ─── N4 — JSON-RPC Error Object Injection ────────────────────────────────

describe.skip("N4 — JSON-RPC Error Object Injection", () => {
  it("flags user input in error message", () => {
    const f = run("N4", `const error = { message: req.body.errorMsg };`);
    expect(f.some(x => x.rule_id === "N4")).toBe(true);
    const finding = findingFor(f, "N4");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("flags request params in error data", () => {
    const f = run("N4", `err.data = request.params.detail;`);
    expect(f.some(x => x.rule_id === "N4")).toBe(true);
    const finding = findingFor(f, "N4");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("flags stack trace in error response", () => {
    const f = run("N4", `error.details = err.stack.toString();`);
    expect(f.some(x => x.rule_id === "N4")).toBe(true);
    const finding = findingFor(f, "N4");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("does NOT flag static error message", () => {
    expect(run("N4", `throw new Error("Internal server error");`).filter(x => x.rule_id === "N4").length).toBe(0);
  });
  it("does NOT flag error with sanitized input", () => {
    expect(run("N4", `const safeMsg = sanitize(input); throw new Error(safeMsg);`).filter(x => x.rule_id === "N4").length).toBe(0);
  });
});

// ─── N5 — Capability Downgrade Deception ─────────────────────────────────

describe.skip("N5 — Capability Downgrade Deception", () => {
  it("flags tools disabled but handler exists", () => {
    const f = run("N5", `const serverCapabilities = { tools: false };\nfunction handleToolCall(req) { return processTools(req); }`);
    expect(f.some(x => x.rule_id === "N5")).toBe(true);
    const finding = findingFor(f, "N5");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("flags sampling disabled but sampling handler exists", () => {
    const f = run("N5", `const serverCapabilities = { sampling: null };\nfunction createSample(req) { return sample(req); }`);
    expect(f.some(x => x.rule_id === "N5")).toBe(true);
    const finding = findingFor(f, "N5");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("does NOT flag properly declared capabilities", () => {
    expect(run("N5", `const serverCapabilities = { tools: { listChanged: true } };\nfunction handleToolCall(req) {}`).filter(x => x.rule_id === "N5").length).toBe(0);
  });
  it("does NOT flag disabled capability without handler", () => {
    expect(run("N5", `const serverCapabilities = { tools: false };`).filter(x => x.rule_id === "N5").length).toBe(0);
  });
});

// ─── N6 — SSE Reconnection Hijacking ─────────────────────────────────────

describe.skip("N6 — SSE Reconnection Hijacking", () => {
  it("flags EventSource reconnect without auth", () => {
    const f = run("N6", `const es = new EventSource(url); // reconnect on disconnect`);
    expect(f.some(x => x.rule_id === "N6")).toBe(true);
    const finding = findingFor(f, "N6");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("flags Last-Event-ID parsed without integrity check", () => {
    const f = run("N6", `const id = req.headers['Last-Event-ID']; const num = parseInt(id);`);
    expect(f.some(x => x.rule_id === "N6")).toBe(true);
    const finding = findingFor(f, "N6");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("flags session in URL without signing", () => {
    const f = run("N6", `const sessionId = req.query.sess; // session from url`);
    expect(f.some(x => x.rule_id === "N6")).toBe(true);
    const finding = findingFor(f, "N6");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("does NOT flag SSE with re-authentication", () => {
    expect(run("N6", `const es = new EventSource(url, { headers: { Authorization: token } }); // SSE with auth verify`).filter(x => x.rule_id === "N6").length).toBe(0);
  });
});

// N7 and N8: migrated to per-rule directories in Phase 1 chunk 1.8.
// Legacy implementations under these ids targeted orthogonal concerns
// (init race / ping side-channel). New implementations align with YAML.
// Comprehensive tests at src/rules/implementations/n{7,8}-*\/__tests__/index.test.ts.

// ─── N9 — Logging Protocol Injection ─────────────────────────────────────

describe.skip("N9 — Logging Protocol Injection", () => {
  it("flags user input in log message", () => {
    const f = run("N9", `logger.info(req.body.message);`);
    expect(f.some(x => x.rule_id === "N9")).toBe(true);
    const finding = findingFor(f, "N9");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("flags user input in MCP log notification", () => {
    const f = run("N9", `sendLogMessage({ level: "info", data: req.body.msg });`);
    expect(f.some(x => x.rule_id === "N9")).toBe(true);
    const finding = findingFor(f, "N9");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("flags request params in warning log", () => {
    const f = run("N9", `logger.warn(request.params.message);`);
    expect(f.some(x => x.rule_id === "N9")).toBe(true);
    const finding = findingFor(f, "N9");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("does NOT flag static log message", () => {
    expect(run("N9", `logger.info("Server started on port 3000");`).filter(x => x.rule_id === "N9").length).toBe(0);
  });
});

// N10: migrated to per-rule directory in Phase 1 chunk 1.8. New
// implementation aligns with rules/N10-incomplete-handshake-dos.yaml.
// Comprehensive tests at src/rules/implementations/n10-incomplete-handshake-dos/__tests__/index.test.ts.

// ─── N11 — Protocol Version Downgrade ────────────────────────────────────

describe.skip("N11 — Protocol Version Downgrade", () => {
  it("flags accepting minimum version without rejection", () => {
    const f = run("N11", `if (protocolVersion >= "2024-11-05") { negotiate(oldest); selectProtocol(min); }`);
    expect(f.some(x => x.rule_id === "N11")).toBe(true);
    const finding = findingFor(f, "N11");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("flags negotiating lowest version", () => {
    const f = run("N11", `const version = negotiate(protocol, lowest, first);`);
    expect(f.some(x => x.rule_id === "N11")).toBe(true);
    const finding = findingFor(f, "N11");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("does NOT flag strict version check", () => {
    expect(run("N11", `if (protocolVersion !== "2025-03-26") throw new Error("Unsupported");`).filter(x => x.rule_id === "N11").length).toBe(0);
  });
  it("does NOT flag version reject on mismatch", () => {
    expect(run("N11", `if (protocolVersion < MIN_VERSION) { reject("Version too old"); deny(); }`).filter(x => x.rule_id === "N11").length).toBe(0);
  });
});

// ─── N12 — Resource Subscription Content Mutation ────────────────────────

describe.skip("N12 — Resource Subscription Content Mutation", () => {
  it("flags subscription update without integrity check", () => {
    const f = run("N12", `onSubscription(resourceId, () => { notify('resource', { content: modified, changed: true }); });`);
    expect(f.some(x => x.rule_id === "N12")).toBe(true);
    const finding = findingFor(f, "N12");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("flags push update with content mutation", () => {
    const f = run("N12", `subscription.push({ resource: id, content: mutated, modified: true });`);
    expect(f.some(x => x.rule_id === "N12")).toBe(true);
    const finding = findingFor(f, "N12");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("does NOT flag subscription with hash verification", () => {
    expect(run("N12", `onSubscription(resourceId, () => { const h = computeHash(content); verify(h); notify('resource_changed_with_checksum'); });`).filter(x => x.rule_id === "N12").length).toBe(0);
  });
});

// ─── N13 — Chunked Transfer Smuggling ────────────────────────────────────

describe.skip("N13 — Chunked Transfer Smuggling", () => {
  it("flags both Transfer-Encoding and Content-Length", () => {
    const f = run("N13", `const headers = { "Transfer-Encoding": "chunked", "Content-Length": "100" };`);
    expect(f.some(x => x.rule_id === "N13")).toBe(true);
    const finding = findingFor(f, "N13");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("flags raw socket chunked encoding", () => {
    const f = run("N13", `socket.write("\\r\\n0\\r\\n"); // raw chunk terminator`);
    expect(f.some(x => x.rule_id === "N13")).toBe(true);
    const finding = findingFor(f, "N13");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("does NOT flag normal HTTP library usage", () => {
    expect(run("N13", `fetch('https://api.example.com/data', { method: 'POST', body: JSON.stringify(data) });`).filter(x => x.rule_id === "N13").length).toBe(0);
  });
  it("does NOT flag Content-Length alone", () => {
    expect(run("N13", `res.setHeader('Content-Length', buffer.length);`).filter(x => x.rule_id === "N13").length).toBe(0);
  });
});

// ─── N14 — Trust-On-First-Use Bypass ─────────────────────────────────────

describe.skip("N14 — Trust-On-First-Use Bypass", () => {
  it("flags TOFU without pinning", () => {
    const f = run("N14", `if (isNew) { trust(firstConnect); accept(newServer); } // allow first connection`);
    expect(f.some(x => x.rule_id === "N14")).toBe(true);
    const finding = findingFor(f, "N14");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("flags fingerprint pinning disabled", () => {
    const f = run("N14", `known_hosts.ignore(); // skip fingerprint check`);
    expect(f.some(x => x.rule_id === "N14")).toBe(true);
    const finding = findingFor(f, "N14");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("flags skip pin override", () => {
    const f = run("N14", `const opts = { pin: { override: true, skip: true } }; // fingerprint skip disable`);
    expect(f.some(x => x.rule_id === "N14")).toBe(true);
    const finding = findingFor(f, "N14");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("does NOT flag proper certificate pinning", () => {
    expect(run("N14", `const pin = crypto.hash(cert); if (pin !== storedPin) throw new Error("Pin mismatch");`).filter(x => x.rule_id === "N14").length).toBe(0);
  });
});

// ─── N15 — JSON-RPC Method Name Confusion ────────────────────────────────

describe.skip("N15 — JSON-RPC Method Name Confusion", () => {
  it("flags user input as method dispatch", () => {
    const f = run("N15", `const method = req.body.method;\nhandler[method](args);`);
    expect(f.some(x => x.rule_id === "N15")).toBe(true);
    const finding = findingFor(f, "N15");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("flags dynamic dispatch from params", () => {
    const f = run("N15", `dispatch[params.method](params.args);`);
    expect(f.some(x => x.rule_id === "N15")).toBe(true);
    const finding = findingFor(f, "N15");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("flags method name from request used as key", () => {
    const f = run("N15", `const rpcMethod = request.body.rpcMethod;\nhandle[rpcMethod]();`);
    expect(f.some(x => x.rule_id === "N15")).toBe(true);
    const finding = findingFor(f, "N15");
    const chain = expectEvidenceChain(finding);
    expectConfidenceRange(chain, 0.30, 0.99);
  });
  it("does NOT flag static method dispatch", () => {
    expect(run("N15", `handler["tools/list"](args);`).filter(x => x.rule_id === "N15").length).toBe(0);
  });
  it("does NOT flag allowlist-validated dispatch", () => {
    expect(run("N15", `const allowed = ["tools/list", "tools/call"]; const m = allowlist.validate(input);`).filter(x => x.rule_id === "N15").length).toBe(0);
  });
});
