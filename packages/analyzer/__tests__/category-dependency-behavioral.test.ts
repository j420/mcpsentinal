/**
 * Categories: Dependency Analysis (D1-D7) + Behavioral Analysis (E1-E4) — 45 tests
 */
import { describe, it, expect } from "vitest";
import type { AnalysisContext } from "../src/engine.js";
import { getTypedRule } from "../src/rules/base.js";
import "../src/rules/index.js";

function ctx(overrides: Partial<AnalysisContext> = {}): AnalysisContext {
  return { server: { id: "t", name: "test", description: null, github_url: null }, tools: [], source_code: null, dependencies: [], connection_metadata: null, ...overrides };
}
function run(id: string, c: AnalysisContext) { return getTypedRule(id)!.analyze(c); }

describe("D1 — Known CVEs", () => {
  it("flags dependency with CVE", () => {
    const f = run("D1", ctx({ dependencies: [{ name: "lodash", version: "4.17.15", has_known_cve: true, cve_ids: ["CVE-2020-8203"], last_updated: "2020-01-01" }] }));
    expect(f.length).toBeGreaterThan(0); expect(f[0].rule_id).toBe("D1"); expect(f[0].evidence).toContain("CVE-2020-8203");
  });
  it("flags multiple CVEs", () => {
    const f = run("D1", ctx({ dependencies: [{ name: "express", version: "4.16.0", has_known_cve: true, cve_ids: ["CVE-2022-24999", "CVE-2024-12345"], last_updated: "2022-01-01" }] }));
    expect(f.length).toBeGreaterThan(0); expect(f[0].evidence).toContain("CVE-2022-24999");
  });
  it("does NOT flag clean dependency", () => {
    expect(run("D1", ctx({ dependencies: [{ name: "express", version: "4.18.0", has_known_cve: false, cve_ids: [], last_updated: "2024-01-01" }] })).length).toBe(0);
  });
});

describe("D2 — Abandoned Dependencies", () => {
  it("flags >12 month old dependency", () => {
    const twoYearsAgo = new Date(Date.now() - 730 * 24 * 60 * 60 * 1000).toISOString();
    const f = run("D2", ctx({ dependencies: [{ name: "old-pkg", version: "1.0.0", has_known_cve: false, cve_ids: [], last_updated: twoYearsAgo }] }));
    expect(f.length).toBeGreaterThan(0); expect(f[0].rule_id).toBe("D2");
  });
  it("does NOT flag recently updated", () => {
    expect(run("D2", ctx({ dependencies: [{ name: "fresh", version: "1.0.0", has_known_cve: false, cve_ids: [], last_updated: new Date().toISOString() }] })).length).toBe(0);
  });
});

describe("D4 — Excessive Dependency Count", () => {
  it("flags >50 dependencies", () => {
    const deps = Array.from({ length: 55 }, (_, i) => ({ name: `dep-${i}`, version: "1.0.0", has_known_cve: false, cve_ids: [], last_updated: "" }));
    expect(run("D4", ctx({ dependencies: deps })).length).toBeGreaterThan(0);
  });
  it("does NOT flag 10 dependencies", () => {
    const deps = Array.from({ length: 10 }, (_, i) => ({ name: `dep-${i}`, version: "1.0.0", has_known_cve: false, cve_ids: [], last_updated: "" }));
    expect(run("D4", ctx({ dependencies: deps })).length).toBe(0);
  });
});

describe("D5 — Known Malicious Packages", () => {
  it("flags event-stream", () => {
    const f = run("D5", ctx({ dependencies: [{ name: "event-stream", version: "3.3.6", has_known_cve: false, cve_ids: [], last_updated: "" }] }));
    expect(f.length).toBeGreaterThan(0); expect(f[0].rule_id).toBe("D5"); expect(f[0].confidence).toBeGreaterThan(0.60);
  });
  it("flags MCP typosquat @mcp/sdk", () => {
    const f = run("D5", ctx({ dependencies: [{ name: "@mcp/sdk", version: "1.0.0", has_known_cve: false, cve_ids: [], last_updated: "" }] }));
    expect(f.length).toBeGreaterThan(0);
  });
  it("does NOT flag legitimate package", () => {
    expect(run("D5", ctx({ dependencies: [{ name: "@modelcontextprotocol/sdk", version: "1.0.0", has_known_cve: false, cve_ids: [], last_updated: "" }] })).length).toBe(0);
  });
});

describe("D6 — Weak Cryptography", () => {
  it("flags md5 package", () => {
    const f = run("D6", ctx({ dependencies: [{ name: "md5", version: "2.3.0", has_known_cve: false, cve_ids: [], last_updated: "" }] }));
    expect(f.length).toBeGreaterThan(0); expect(f[0].rule_id).toBe("D6");
  });
  it("flags bcrypt-nodejs", () => {
    expect(run("D6", ctx({ dependencies: [{ name: "bcrypt-nodejs", version: "0.0.3", has_known_cve: false, cve_ids: [], last_updated: "" }] })).length).toBeGreaterThan(0);
  });
  it("does NOT flag bcrypt (correct package)", () => {
    expect(run("D6", ctx({ dependencies: [{ name: "bcrypt", version: "5.0.0", has_known_cve: false, cve_ids: [], last_updated: "" }] })).length).toBe(0);
  });
});

describe("D7 — Dependency Confusion", () => {
  it("flags scoped package with version 9999", () => {
    const f = run("D7", ctx({ dependencies: [{ name: "@internal/utils", version: "9999.0.0", has_known_cve: false, cve_ids: [], last_updated: "" }] }));
    expect(f.length).toBeGreaterThan(0); expect(f[0].rule_id).toBe("D7");
  });
  it("does NOT flag normal versioned scoped package", () => {
    expect(run("D7", ctx({ dependencies: [{ name: "@types/node", version: "20.0.0", has_known_cve: false, cve_ids: [], last_updated: "" }] })).length).toBe(0);
  });
});

describe("E1 — No Authentication", () => {
  it("flags no auth required", () => {
    const f = run("E1", ctx({ connection_metadata: { auth_required: false, transport: "https", response_time_ms: 100 } }));
    expect(f.length).toBeGreaterThan(0); expect(f[0].rule_id).toBe("E1");
  });
  it("flags no auth on HTTP transport", () => {
    const f = run("E1", ctx({ connection_metadata: { auth_required: false, transport: "http", response_time_ms: 50 } }));
    expect(f.length).toBeGreaterThan(0); expect(f[0].rule_id).toBe("E1");
    expect(f[0].evidence).toContain("authentication");
  });
  it("flags no auth with fast response", () => {
    const f = run("E1", ctx({ connection_metadata: { auth_required: false, transport: "wss", response_time_ms: 10 } }));
    expect(f.length).toBeGreaterThan(0); expect(f[0].severity).toBe("medium");
  });
  it("does NOT flag when auth required", () => {
    expect(run("E1", ctx({ connection_metadata: { auth_required: true, transport: "https", response_time_ms: 100 } })).length).toBe(0);
  });
  it("does NOT flag when no connection metadata (null)", () => {
    expect(run("E1", ctx({ connection_metadata: null })).length).toBe(0);
  });
  it("does NOT flag when connection_metadata is absent", () => {
    expect(run("E1", ctx()).length).toBe(0);
  });
});

describe("E2 — Insecure Transport", () => {
  it("flags HTTP transport", () => {
    const f = run("E2", ctx({ connection_metadata: { auth_required: true, transport: "http", response_time_ms: 100 } }));
    expect(f.length).toBeGreaterThan(0); expect(f[0].rule_id).toBe("E2");
    expect(f[0].evidence).toContain("http");
  });
  it("flags WS transport", () => {
    const f = run("E2", ctx({ connection_metadata: { auth_required: true, transport: "ws", response_time_ms: 100 } }));
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].severity).toBe("high");
  });
  it("flags HTTP even with auth", () => {
    expect(run("E2", ctx({ connection_metadata: { auth_required: true, transport: "http", response_time_ms: 50 } })).length).toBeGreaterThan(0);
  });
  it("does NOT flag HTTPS", () => {
    expect(run("E2", ctx({ connection_metadata: { auth_required: true, transport: "https", response_time_ms: 100 } })).length).toBe(0);
  });
  it("does NOT flag WSS", () => {
    expect(run("E2", ctx({ connection_metadata: { auth_required: true, transport: "wss", response_time_ms: 100 } })).length).toBe(0);
  });
  it("does NOT flag when no connection metadata", () => {
    expect(run("E2", ctx({ connection_metadata: null })).length).toBe(0);
  });
});

describe("E3 — Response Time Anomaly", () => {
  it("flags >10s response", () => {
    const f = run("E3", ctx({ connection_metadata: { auth_required: true, transport: "https", response_time_ms: 15000 } }));
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].rule_id).toBe("E3");
    expect(f[0].severity).toBe("low");
  });
  it("flags exactly at boundary (>10000ms)", () => {
    expect(run("E3", ctx({ connection_metadata: { auth_required: true, transport: "https", response_time_ms: 10001 } })).length).toBeGreaterThan(0);
  });
  it("flags very slow response (60s)", () => {
    const f = run("E3", ctx({ connection_metadata: { auth_required: true, transport: "https", response_time_ms: 60000 } }));
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].evidence).toContain("60000");
  });
  it("does NOT flag 200ms response", () => {
    expect(run("E3", ctx({ connection_metadata: { auth_required: true, transport: "https", response_time_ms: 200 } })).length).toBe(0);
  });
  it("does NOT flag exactly 10s response", () => {
    expect(run("E3", ctx({ connection_metadata: { auth_required: true, transport: "https", response_time_ms: 10000 } })).length).toBe(0);
  });
  it("does NOT flag when no connection metadata", () => {
    expect(run("E3", ctx({ connection_metadata: null })).length).toBe(0);
  });
});

describe("E4 — Excessive Tool Count", () => {
  it("flags >50 tools", () => {
    const tools = Array.from({ length: 55 }, (_, i) => ({ name: `tool_${i}`, description: `Tool ${i}`, input_schema: null }));
    const f = run("E4", ctx({ tools }));
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].rule_id).toBe("E4");
    expect(f[0].evidence).toContain("55");
  });
  it("flags exactly 51 tools", () => {
    const tools = Array.from({ length: 51 }, (_, i) => ({ name: `tool_${i}`, description: `Tool ${i}`, input_schema: null }));
    expect(run("E4", ctx({ tools })).length).toBeGreaterThan(0);
  });
  it("flags 100 tools with severity medium", () => {
    const tools = Array.from({ length: 100 }, (_, i) => ({ name: `tool_${i}`, description: `Tool ${i}`, input_schema: null }));
    const f = run("E4", ctx({ tools }));
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].severity).toBe("medium");
  });
  it("does NOT flag 50 tools (boundary)", () => {
    const tools = Array.from({ length: 50 }, (_, i) => ({ name: `tool_${i}`, description: `Tool ${i}`, input_schema: null }));
    expect(run("E4", ctx({ tools })).length).toBe(0);
  });
  it("does NOT flag 5 tools", () => {
    const tools = Array.from({ length: 5 }, (_, i) => ({ name: `tool_${i}`, description: `Tool ${i}`, input_schema: null }));
    expect(run("E4", ctx({ tools })).length).toBe(0);
  });
  it("does NOT flag 0 tools", () => {
    expect(run("E4", ctx({ tools: [] })).length).toBe(0);
  });
});
