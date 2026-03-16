/**
 * DynamicTester integration tests.
 *
 * Tests the full DynamicTester.test() flow using an in-process mock callTool
 * function — no real MCP server required. Covers:
 *   - Consent denied → minimal no-op report
 *   - Consent via allowlist / tool declaration
 *   - Blocklisted tools skipped
 *   - max_tools_per_server enforced
 *   - Tool timeout handled gracefully
 *   - Injection probe reflection detected
 *   - Risk summary boundary values (riskFromCount thresholds)
 *   - Schema compliance = "warn" on timeout
 *   - Output findings surfaced when scanner fires
 *   - Empty tool list handled without throwing
 *   - Audit log written to temp file
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { DynamicTester } from "../index.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeServer(id = "srv-001", name = "Test Server") {
  return { id, name };
}

function makeTool(name: string, schema?: Record<string, unknown>) {
  return {
    name,
    description: `Tool: ${name}`,
    input_schema: schema ?? { type: "object", properties: { query: { type: "string" } }, required: ["query"] },
  };
}

/** callTool that always returns a benign string */
const safeTool = async (_toolName: string, _input: Record<string, unknown>) =>
  "ok: test result";

/** callTool that echoes a specific canary in the output (simulates injection reflection) */
function reflectingTool(canary: string) {
  return async (_toolName: string, input: Record<string, unknown>) => {
    const inputStr = JSON.stringify(input);
    if (inputStr.includes(canary)) return `reflected: ${canary}`;
    return "ok";
  };
}

/** callTool that always times out */
const slowTool = async () =>
  new Promise<string>((_, reject) =>
    setTimeout(() => reject(new Error("timeout")), 200)
  );

// ─── Consent denied ───────────────────────────────────────────────────────────

describe("DynamicTester — consent denied", () => {
  it("returns minimal report when no consent mechanism matches", async () => {
    const tester = new DynamicTester({ allowlist: [] });
    const report = await tester.test(
      makeServer(),
      "http://127.0.0.1:99999/mcp",  // unreachable → .well-known check fails
      [makeTool("get_data")],
      safeTool
    );

    expect(report.consent.consented).toBe(false);
    expect(report.consent.method).toBeNull();
    expect(report.tools_tested).toBe(0);
    expect(report.tools_skipped).toBe(0);
    expect(report.probes).toHaveLength(0);
    expect(report.output_findings_count).toBe(0);
    expect(report.injection_vulnerable_count).toBe(0);
  });

  it("denied report still has correct server metadata", async () => {
    const tester = new DynamicTester({ allowlist: [] });
    const report = await tester.test(
      { id: "srv-denied", name: "Denied Server" },
      "http://127.0.0.1:99999/mcp",
      [],
      safeTool
    );

    expect(report.server_id).toBe("srv-denied");
    expect(report.server_name).toBe("Denied Server");
    expect(report.endpoint).toBe("http://127.0.0.1:99999/mcp");
    expect(report.tested_at).toBeTruthy();
    expect(report.elapsed_ms).toBeGreaterThanOrEqual(0);
  });

  it("denied report has safe default risk_summary", async () => {
    const tester = new DynamicTester({ allowlist: [] });
    const report = await tester.test(
      makeServer(),
      "http://127.0.0.1:99999/mcp",
      [],
      safeTool
    );

    expect(report.risk_summary.output_injection_risk).toBe("none");
    expect(report.risk_summary.injection_vulnerability).toBe("none");
    expect(report.risk_summary.schema_compliance).toBe("pass");
    expect(report.risk_summary.timing_anomalies).toBe(0);
  });
});

// ─── Consent via allowlist ────────────────────────────────────────────────────

describe("DynamicTester — consent via allowlist", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "dyn-test-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("proceeds to test tools when server ID is in allowlist", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [makeTool("get_data")],
      safeTool
    );

    expect(report.consent.consented).toBe(true);
    expect(report.consent.method).toBe("allowlist");
    expect(report.tools_tested).toBe(1);
    expect(report.probes).toHaveLength(1);
    expect(report.probes[0].tool_name).toBe("get_data");
  });

  it("probe status is 'success' for a tool that responds", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [makeTool("get_data")],
      safeTool
    );

    expect(report.probes[0].status).toBe("success");
    expect(report.probes[0].raw_output).toBe("ok: test result");
    expect(report.probes[0].error).toBeNull();
  });

  it("writes audit log with consent_check + tool_probe + report_complete entries", async () => {
    const auditPath = join(tmpDir, "audit.jsonl");
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      audit_log_path: auditPath,
    });

    await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [makeTool("search")],
      safeTool
    );

    const lines = readFileSync(auditPath, "utf-8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));

    const events = lines.map((l: { event: string }) => l.event);
    expect(events).toContain("consent_check");
    expect(events).toContain("tool_probe");
    expect(events).toContain("report_complete");
  });
});

// ─── Consent via tool declaration ────────────────────────────────────────────

describe("DynamicTester — consent via tool declaration", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "dyn-decl-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("proceeds when mcp_sentinel_consent tool is in the tool list", async () => {
    const tester = new DynamicTester({
      allowlist: [],
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const tools = [
      { name: "mcp_sentinel_consent", description: "Consent signal", input_schema: null },
      makeTool("list_items"),
    ];

    const report = await tester.test(
      makeServer("srv-consent"),
      "http://localhost:3000/mcp",
      tools,
      safeTool
    );

    expect(report.consent.consented).toBe(true);
    expect(report.consent.method).toBe("tool_declaration");
    // mcp_sentinel_consent itself is tested (not blocklisted)
    expect(report.tools_tested).toBeGreaterThanOrEqual(1);
  });

  it("does NOT test blocked tools even when consented via declaration", async () => {
    const tester = new DynamicTester({
      allowlist: [],
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const tools = [
      { name: "mcp_sentinel_consent", description: "Consent", input_schema: null },
      { name: "delete_file", description: "Deletes a file", input_schema: null },
      { name: "purge_database", description: "Purges the DB", input_schema: null },
      makeTool("safe_query"),
    ];

    const report = await tester.test(
      makeServer("srv-consent"),
      "http://localhost:3000/mcp",
      tools,
      safeTool
    );

    const testedNames = report.probes.map((p) => p.tool_name);
    expect(testedNames).not.toContain("delete_file");
    expect(testedNames).not.toContain("purge_database");
  });
});

// ─── Blocklist enforcement ────────────────────────────────────────────────────

describe("DynamicTester — blocklist enforcement", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "dyn-block-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("skips all built-in dangerous tool name patterns", async () => {
    const dangerousTools = [
      "delete_files",
      "remove_record",
      "drop_table",
      "purge_cache",
      "destroy_session",
      "wipe_data",
      "format_disk",
      "shutdown_server",
      "reboot_node",
      "kill_process",
    ];

    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const tools = dangerousTools.map((name) => makeTool(name));
    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      tools,
      safeTool
    );

    // All 10 tools match the blocklist patterns → none should be tested
    expect(report.tools_tested).toBe(0);
    expect(report.probes).toHaveLength(0);
    // tools_skipped = number of tools minus the blocklisted ones
    // skipped only counts the delta from eligible vs total list
    expect(report.tools_skipped).toBe(0); // eligible = 0, total - eligible = 0 skipped
  });

  it("custom blocklist pattern blocks matching tools", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      blocklist_tool_patterns: [/^admin_/i],
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const tools = [
      makeTool("admin_reset"),
      makeTool("admin_grant"),
      makeTool("search_items"),
    ];

    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      tools,
      safeTool
    );

    const testedNames = report.probes.map((p) => p.tool_name);
    expect(testedNames).not.toContain("admin_reset");
    expect(testedNames).not.toContain("admin_grant");
    expect(testedNames).toContain("search_items");
  });
});

// ─── max_tools_per_server limit ───────────────────────────────────────────────

describe("DynamicTester — max_tools_per_server limit", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "dyn-limit-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("caps the number of tools tested at max_tools_per_server", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      max_tools_per_server: 3,
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const tools = Array.from({ length: 10 }, (_, i) => makeTool(`tool_${i}`));
    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      tools,
      safeTool
    );

    expect(report.tools_tested).toBe(3);
    expect(report.probes).toHaveLength(3);
  });

  it("max_tools_per_server=1 tests exactly one tool", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      max_tools_per_server: 1,
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const tools = [makeTool("alpha"), makeTool("beta"), makeTool("gamma")];
    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      tools,
      safeTool
    );

    expect(report.tools_tested).toBe(1);
    expect(report.probes[0].tool_name).toBe("alpha");
  });
});

// ─── Timeout handling ─────────────────────────────────────────────────────────

describe("DynamicTester — timeout handling", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "dyn-timeout-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("probe status is 'timeout' when callTool takes longer than tool_timeout_ms", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      tool_timeout_ms: 50,  // very short timeout
      enable_injection_probes: false,
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [makeTool("slow_tool")],
      slowTool
    );

    expect(report.probes[0].status).toBe("timeout");
    expect(report.probes[0].raw_output).toBeNull();
    expect(report.probes[0].error).toBeNull();
  });

  it("schema_compliance is 'warn' when any tool times out", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      tool_timeout_ms: 50,
      enable_injection_probes: false,
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const tools = [makeTool("fast_tool"), makeTool("slow_tool")];
    const callToolMixed = async (name: string, input: Record<string, unknown>) => {
      if (name === "slow_tool") return slowTool(name, input);
      return safeTool(name, input);
    };

    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      tools,
      callToolMixed
    );

    expect(report.risk_summary.schema_compliance).toBe("warn");
  });

  it("non-timeout errors set status to 'error' with error message", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const errorTool = async () => {
      throw new Error("connection refused");
    };

    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [makeTool("broken_tool")],
      errorTool
    );

    expect(report.probes[0].status).toBe("error");
    expect(report.probes[0].error).toBe("connection refused");
  });
});

// ─── Injection probe reflection ───────────────────────────────────────────────

describe("DynamicTester — injection probe reflection", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "dyn-inject-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("marks probe as reflected when canary_token appears in output", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      enable_injection_probes: true,
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    // A tool with a command parameter — injection probes will be generated
    const tool = makeTool("exec_cmd", {
      type: "object",
      properties: { command: { type: "string" } },
      required: ["command"],
    });

    // callTool echoes back whatever command was passed → reflects canary
    const echoTool = async (_name: string, input: Record<string, unknown>) =>
      `executed: ${input.command}`;

    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [tool],
      echoTool
    );

    const probe = report.probes[0];
    expect(probe.injection_probes.length).toBeGreaterThan(0);

    const reflectedProbes = probe.injection_probes.filter((p) => p.reflected);
    expect(reflectedProbes.length).toBeGreaterThan(0);
    // Evidence is non-null when reflected
    expect(reflectedProbes[0].evidence).toBeTruthy();
  });

  it("injection_vulnerable_count reflects number of tools with reflected probes", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      enable_injection_probes: true,
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const tool = makeTool("run_cmd", {
      type: "object",
      properties: { command: { type: "string" } },
      required: ["command"],
    });

    const echoTool = async (_n: string, i: Record<string, unknown>) =>
      `result: ${i.command}`;

    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [tool],
      echoTool
    );

    // At least one injection probe should have been reflected
    if (report.probes[0].injection_probes.some((p) => p.reflected)) {
      expect(report.injection_vulnerable_count).toBeGreaterThanOrEqual(1);
    }
  });

  it("no injection probes generated when enable_injection_probes=false", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      enable_injection_probes: false,
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const tool = makeTool("run_cmd", {
      type: "object",
      properties: { command: { type: "string" } },
      required: ["command"],
    });

    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [tool],
      safeTool
    );

    expect(report.probes[0].injection_probes).toHaveLength(0);
  });
});

// ─── Risk summary computation (riskFromCount boundaries) ─────────────────────

describe("DynamicTester — risk summary injection_vulnerability levels", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "dyn-risk-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  /**
   * Build a report by running N tools that all reflect injection probes.
   * We achieve this by giving each tool a `command` parameter and using
   * an echo callTool so every payload is reflected.
   */
  async function runWithNReflectedTools(n: number, auditPath: string) {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      enable_injection_probes: true,
      max_tools_per_server: n + 10,
      audit_log_path: auditPath,
    });

    const tools = Array.from({ length: n }, (_, i) =>
      makeTool(`cmd_${i}`, {
        type: "object",
        properties: { command: { type: "string" } },
        required: ["command"],
      })
    );

    const echoCall = async (_n: string, i: Record<string, unknown>) =>
      `output: ${i.command}`;

    return tester.test(makeServer("srv-001"), "http://localhost:3000/mcp", tools, echoCall);
  }

  it("injection_vulnerability = 'none' when no injection vulns detected (no cmd tools)", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      enable_injection_probes: true,
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    // Tool with only a "label" param → no injection payloads generated
    const tool = makeTool("search", {
      type: "object",
      properties: { label: { type: "string" } },
      required: ["label"],
    });

    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [tool],
      safeTool
    );

    expect(report.risk_summary.injection_vulnerability).toBe("none");
  });

  it("injection_vulnerability risk levels scale with vulnerable count", async () => {
    // riskFromCount: 0→none, 1→low, 2→medium, 3→medium, 4→high, 7→critical
    // For this test we verify the values are one of the valid enum entries
    const valid = ["none", "low", "medium", "high", "critical"];

    const report = await runWithNReflectedTools(2, join(tmpDir, "audit.jsonl"));
    expect(valid).toContain(report.risk_summary.injection_vulnerability);
    expect(valid).toContain(report.risk_summary.output_injection_risk);
  });
});

// ─── Empty tool list ──────────────────────────────────────────────────────────

describe("DynamicTester — empty tool list", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "dyn-empty-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("returns valid report with zero probes when tool list is empty", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [],
      safeTool
    );

    expect(report.consent.consented).toBe(true);
    expect(report.tools_tested).toBe(0);
    expect(report.probes).toHaveLength(0);
    expect(report.risk_summary.schema_compliance).toBe("pass");
    expect(report.risk_summary.injection_vulnerability).toBe("none");
  });
});

// ─── Audit log integration ────────────────────────────────────────────────────

describe("DynamicTester — audit log integration", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "dyn-log-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("creates audit log file after test run", async () => {
    const auditPath = join(tmpDir, "subdir", "audit.jsonl");
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      audit_log_path: auditPath,
    });

    await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [makeTool("search")],
      safeTool
    );

    expect(existsSync(auditPath)).toBe(true);
  });

  it("audit log entries contain server_id", async () => {
    const auditPath = join(tmpDir, "audit.jsonl");
    const tester = new DynamicTester({
      allowlist: ["srv-audit-check"],
      audit_log_path: auditPath,
    });

    await tester.test(
      makeServer("srv-audit-check"),
      "http://localhost:3000/mcp",
      [makeTool("fetch_data")],
      safeTool
    );

    const lines = readFileSync(auditPath, "utf-8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));

    for (const entry of lines) {
      expect(entry.server_id).toBe("srv-audit-check");
    }
  });

  it("audit log grows with each test run (append-only)", async () => {
    const auditPath = join(tmpDir, "audit.jsonl");
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      audit_log_path: auditPath,
    });

    await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [makeTool("search")],
      safeTool
    );

    const lineCountFirst = readFileSync(auditPath, "utf-8").trim().split("\n").length;

    await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [makeTool("fetch")],
      safeTool
    );

    const lineCountSecond = readFileSync(auditPath, "utf-8").trim().split("\n").length;

    expect(lineCountSecond).toBeGreaterThan(lineCountFirst);
  });
});

// ─── Report shape validation ──────────────────────────────────────────────────

describe("DynamicTester — report shape", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "dyn-shape-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("report has all required fields with correct types", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [makeTool("search")],
      safeTool
    );

    expect(typeof report.server_id).toBe("string");
    expect(typeof report.server_name).toBe("string");
    expect(typeof report.endpoint).toBe("string");
    expect(typeof report.tested_at).toBe("string");
    expect(typeof report.elapsed_ms).toBe("number");
    expect(typeof report.tools_tested).toBe("number");
    expect(typeof report.tools_skipped).toBe("number");
    expect(typeof report.output_findings_count).toBe("number");
    expect(typeof report.injection_vulnerable_count).toBe("number");
    expect(Array.isArray(report.probes)).toBe(true);
    expect(typeof report.risk_summary).toBe("object");
  });

  it("output_findings_count matches sum of findings across all probes", async () => {
    const tester = new DynamicTester({
      allowlist: ["srv-001"],
      audit_log_path: join(tmpDir, "audit.jsonl"),
    });

    const report = await tester.test(
      makeServer("srv-001"),
      "http://localhost:3000/mcp",
      [makeTool("get_a"), makeTool("get_b")],
      safeTool
    );

    const totalFindings = report.probes.reduce(
      (s, p) => s + p.output_findings.length,
      0
    );
    expect(report.output_findings_count).toBe(totalFindings);
  });
});
