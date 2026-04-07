/**
 * K4 — Missing Human Confirmation for Destructive Ops
 * K17 — Missing Timeout or Circuit Breaker
 *
 * Comprehensive tests for the TypedRuleV2 migrations from regex to dynamic analysis.
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

// ═══════════════════════════════════════════════════════════════════════════════
// K4 — Missing Human Confirmation for Destructive Ops
// ═══════════════════════════════════════════════════════════════════════════════

describe("K4 True Positives — Tool Schema Inference", () => {
  it("flags delete_file tool without confirmation param", () => {
    const c = ctx({
      tools: [{
        name: "delete_file",
        description: "Delete a file from the filesystem",
        input_schema: { type: "object", properties: { path: { type: "string" } } },
      }],
    });
    const findings = getTypedRule("K4")!.analyze(c);
    expect(findings.some(f => f.rule_id === "K4")).toBe(true);
  });

  it("flags remove_user tool without confirmation param", () => {
    const c = ctx({
      tools: [{
        name: "remove_user",
        description: "Permanently remove a user account",
        input_schema: { type: "object", properties: { user_id: { type: "string" } } },
      }],
    });
    const findings = getTypedRule("K4")!.analyze(c);
    expect(findings.some(f => f.rule_id === "K4")).toBe(true);
  });

  it("flags drop_database tool — bulk destructive", () => {
    const c = ctx({
      tools: [{
        name: "drop_database",
        description: "Drop an entire database. Cannot be undone.",
        input_schema: { type: "object", properties: { db_name: { type: "string" } } },
      }],
    });
    const findings = getTypedRule("K4")!.analyze(c);
    expect(findings.some(f => f.rule_id === "K4")).toBe(true);
  });

  it("flags purge_all tool — bulk operation", () => {
    const c = ctx({
      tools: [{
        name: "purge_all_logs",
        description: "Purge all log files",
        input_schema: { type: "object", properties: {} },
      }],
    });
    const findings = getTypedRule("K4")!.analyze(c);
    expect(findings.some(f => f.rule_id === "K4")).toBe(true);
  });
});

describe("K4 True Negatives — Tool Schema", () => {
  it("does NOT flag delete_file with confirm parameter", () => {
    const c = ctx({
      tools: [{
        name: "delete_file",
        description: "Delete a file",
        input_schema: {
          type: "object",
          properties: {
            path: { type: "string" },
            confirm: { type: "boolean", description: "Must be true to proceed" },
          },
          required: ["path", "confirm"],
        },
      }],
    });
    const findings = getTypedRule("K4")!.analyze(c);
    expect(findings.filter(f => f.rule_id === "K4").length).toBe(0);
  });

  it("does NOT flag delete_file with dry_run parameter", () => {
    const c = ctx({
      tools: [{
        name: "delete_file",
        description: "Delete a file",
        input_schema: {
          type: "object",
          properties: {
            path: { type: "string" },
            dry_run: { type: "boolean" },
          },
        },
      }],
    });
    const findings = getTypedRule("K4")!.analyze(c);
    expect(findings.filter(f => f.rule_id === "K4").length).toBe(0);
  });

  it("does NOT flag read_file tool (not destructive)", () => {
    const c = ctx({
      tools: [{
        name: "read_file",
        description: "Read a file from disk",
        input_schema: { type: "object", properties: { path: { type: "string" } } },
      }],
    });
    const findings = getTypedRule("K4")!.analyze(c);
    expect(findings.filter(f => f.rule_id === "K4").length).toBe(0);
  });

  it("does NOT flag list_users tool (not destructive)", () => {
    const c = ctx({
      tools: [{
        name: "list_users",
        description: "List all users",
        input_schema: { type: "object", properties: {} },
      }],
    });
    const findings = getTypedRule("K4")!.analyze(c);
    expect(findings.filter(f => f.rule_id === "K4").length).toBe(0);
  });
});

describe("K4 True Positives — Source Code Analysis", () => {
  it("flags deleteAll() call without confirmation guard", () => {
    const src = `
      async function handleCleanup(req, res) {
        await db.deleteAll({ table: 'users' });
        res.json({ ok: true });
      }
    `;
    const findings = getTypedRule("K4")!.analyze(ctx({ source_code: src }));
    expect(findings.some(f => f.rule_id === "K4")).toBe(true);
  });

  it("flags destroyBatch() call", () => {
    const src = `
      function purge() {
        records.destroyBatch(ids);
      }
    `;
    const findings = getTypedRule("K4")!.analyze(ctx({ source_code: src }));
    expect(findings.some(f => f.rule_id === "K4")).toBe(true);
  });
});

describe("K4 True Negatives — Source Code", () => {
  it("does NOT flag deleteAll() with confirm() guard", () => {
    const src = `
      async function handleCleanup(req, res) {
        if (await confirm('Delete all records?')) {
          await db.deleteAll({ table: 'users' });
        }
        res.json({ ok: true });
      }
    `;
    const findings = getTypedRule("K4")!.analyze(ctx({ source_code: src }));
    expect(findings.filter(f => f.rule_id === "K4").length).toBe(0);
  });

  it("does NOT flag test file code", () => {
    const src = `
      // __tests__/cleanup.test.ts
      describe('cleanup', () => {
        it('deletes all', async () => {
          await db.deleteAll({ table: 'test_data' });
        });
      });
    `;
    const findings = getTypedRule("K4")!.analyze(ctx({ source_code: src }));
    expect(findings.filter(f => f.rule_id === "K4").length).toBe(0);
  });

  it("does NOT flag when force flag is checked", () => {
    const src = `
      function cleanup(force) {
        if (force) {
          db.deleteAll();
        }
      }
    `;
    const findings = getTypedRule("K4")!.analyze(ctx({ source_code: src }));
    expect(findings.filter(f => f.rule_id === "K4").length).toBe(0);
  });
});

describe("K4 Evidence Chain", () => {
  it("produces evidence chain with schema inference signals", () => {
    const c = ctx({
      tools: [{
        name: "wipe_database",
        description: "Permanently wipe the entire database. Cannot be undone.",
        input_schema: { type: "object", properties: { db: { type: "string" } } },
      }],
    });
    const findings = getTypedRule("K4")!.analyze(c);
    const k4 = findings.find(f => f.rule_id === "K4");
    expect(k4).toBeDefined();

    const chain = k4!.metadata?.evidence_chain as any;
    expect(chain).toBeDefined();
    expect(chain.links.some((l: any) => l.type === "source")).toBe(true);
    expect(chain.links.some((l: any) => l.type === "sink")).toBe(true);
    expect(chain.links.some((l: any) => l.type === "mitigation" && l.present === false)).toBe(true);
    expect(chain.confidence).toBeGreaterThan(0.6);

    // Should reference a compliance framework (EU AI Act or ISO 42001)
    expect(chain.threat_reference?.id).toBeDefined();

    // Should have verification steps
    expect(chain.verification_steps?.length).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// K17 — Missing Timeout or Circuit Breaker
// ═══════════════════════════════════════════════════════════════════════════════

describe("K17 True Positives", () => {
  it("flags fetch() without timeout", () => {
    const src = `
      async function getData() {
        const res = await fetch('https://api.example.com/data');
        return res.json();
      }
    `;
    const findings = getTypedRule("K17")!.analyze(ctx({ source_code: src }));
    expect(findings.some(f => f.rule_id === "K17")).toBe(true);
  });

  it("flags axios.get() without timeout", () => {
    const src = `
      const data = await axios.get('https://api.example.com/users');
    `;
    const findings = getTypedRule("K17")!.analyze(ctx({ source_code: src }));
    expect(findings.some(f => f.rule_id === "K17")).toBe(true);
  });

  it("flags http.request() without timeout", () => {
    const src = `
      const req = http.request('https://api.example.com/data', (res) => {
        res.on('data', chunk => chunks.push(chunk));
      });
    `;
    const findings = getTypedRule("K17")!.analyze(ctx({ source_code: src }));
    expect(findings.some(f => f.rule_id === "K17")).toBe(true);
  });

  it("flags got() without timeout", () => {
    const src = `
      const response = await got('https://api.example.com/data');
    `;
    const findings = getTypedRule("K17")!.analyze(ctx({ source_code: src }));
    expect(findings.some(f => f.rule_id === "K17")).toBe(true);
  });
});

describe("K17 True Negatives", () => {
  it("does NOT flag fetch with AbortController signal", () => {
    const src = `
      async function getData() {
        const controller = new AbortController();
        setTimeout(() => controller.abort(), 5000);
        const res = await fetch('https://api.example.com/data', { signal: controller.signal });
        return res.json();
      }
    `;
    const findings = getTypedRule("K17")!.analyze(ctx({ source_code: src }));
    expect(findings.filter(f => f.rule_id === "K17").length).toBe(0);
  });

  it("does NOT flag axios with timeout option", () => {
    const src = `
      const data = await axios.get('https://api.example.com/users', { timeout: 5000 });
    `;
    const findings = getTypedRule("K17")!.analyze(ctx({ source_code: src }));
    expect(findings.filter(f => f.rule_id === "K17").length).toBe(0);
  });

  it("does NOT flag when axios.defaults.timeout is set", () => {
    const src = `
      axios.defaults.timeout = 30000;
      const data = await axios.get('https://api.example.com/users');
    `;
    const findings = getTypedRule("K17")!.analyze(ctx({ source_code: src }));
    expect(findings.filter(f => f.rule_id === "K17").length).toBe(0);
  });

  it("does NOT flag when AbortSignal.timeout is used", () => {
    const src = `
      const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    `;
    const findings = getTypedRule("K17")!.analyze(ctx({ source_code: src }));
    expect(findings.filter(f => f.rule_id === "K17").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const src = `
      // __tests__/api.test.ts
      it('fetches data', async () => {
        const res = await fetch('http://localhost:3000/api');
        expect(res.ok).toBe(true);
      });
    `;
    const findings = getTypedRule("K17")!.analyze(ctx({ source_code: src }));
    expect(findings.filter(f => f.rule_id === "K17").length).toBe(0);
  });

  it("does NOT flag when no source code", () => {
    const findings = getTypedRule("K17")!.analyze(ctx({ source_code: null }));
    expect(findings.filter(f => f.rule_id === "K17").length).toBe(0);
  });
});

describe("K17 Edge Cases", () => {
  it("lower confidence when circuit breaker dep present", () => {
    const src = `
      const data = await fetch('https://api.example.com/data');
    `;
    const deps = [{ name: "opossum", version: "6.0.0", has_known_cve: false, cve_ids: [], last_updated: "2024-01-01" }];
    const findings = getTypedRule("K17")!.analyze(ctx({ source_code: src, dependencies: deps }));
    const k17 = findings.find(f => f.rule_id === "K17");

    // May still fire (circuit breaker doesn't guarantee coverage of this call)
    // but confidence should be lower
    if (k17) {
      expect(k17.confidence).toBeLessThan(0.9);
    }
  });

  it("does NOT flag got with got.extend timeout", () => {
    const src = `
      const client = got.extend({ timeout: { request: 5000 } });
      const data = await client('https://api.example.com/data');
    `;
    // got.extend sets global timeout — should not flag subsequent got calls
    // Note: the rule checks for got.extend({ timeout }) as a global pattern
    const findings = getTypedRule("K17")!.analyze(ctx({ source_code: src }));
    // This particular call uses `client()` not `got()`, so the pattern may not match
    // The important thing is that got.extend is detected as global timeout
    expect(findings.filter(f => f.rule_id === "K17" && f.evidence.includes("got")).length).toBe(0);
  });
});

describe("K17 Evidence Chain", () => {
  it("produces structured evidence chain with DoS impact", () => {
    const src = `
      async function callApi() {
        const res = await fetch('https://api.example.com/data');
        return res.json();
      }
    `;
    const findings = getTypedRule("K17")!.analyze(ctx({ source_code: src }));
    const k17 = findings.find(f => f.rule_id === "K17");
    expect(k17).toBeDefined();

    const chain = k17!.metadata?.evidence_chain as any;
    expect(chain).toBeDefined();
    expect(chain.links.some((l: any) => l.type === "source")).toBe(true);
    expect(chain.links.some((l: any) => l.type === "sink")).toBe(true);

    // Impact should reference denial-of-service
    const impact = chain.links.find((l: any) => l.type === "impact");
    expect(impact?.impact_type).toBe("denial-of-service");

    // Verification steps present
    expect(chain.verification_steps?.length).toBeGreaterThanOrEqual(1);

    // Confidence factors explain reasoning
    expect(chain.confidence_factors.length).toBeGreaterThanOrEqual(2);
  });

  it("evidence references OWASP ASI08", () => {
    const src = `
      const data = await axios.post('https://api.example.com/submit', payload);
    `;
    const findings = getTypedRule("K17")!.analyze(ctx({ source_code: src }));
    const k17 = findings.find(f => f.rule_id === "K17");

    const chain = k17!.metadata?.evidence_chain as any;
    expect(chain.threat_reference).toBeDefined();
    expect(chain.threat_reference.id).toContain("ASI08");
  });
});
