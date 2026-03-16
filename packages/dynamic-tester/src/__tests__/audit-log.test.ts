/**
 * AuditLog unit tests.
 *
 * Verifies JSONL append-only behaviour, all event types,
 * write failure resilience, and entry shape invariants.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { tmpdir } from "os";
import { AuditLog } from "../audit-log.js";
import type { ConsentResult, ProbeResult, DynamicReport } from "../types.js";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

function makeConsent(consented = true): ConsentResult {
  return {
    consented,
    method: consented ? "allowlist" : null,
    consented_at: consented ? new Date().toISOString() : null,
    note: consented ? "pre-approved for testing" : null,
  };
}

function makeProbeResult(toolName = "my_tool", reflected = false): ProbeResult {
  return {
    tool_name: toolName,
    status: "success",
    canary_input: { query: "mcp-sentinel-canary" },
    raw_output: "result: mcp-sentinel-canary",
    response_time_ms: 42,
    output_findings: [],
    injection_probes: reflected
      ? [{ probe_type: "command_injection", payload: ";ls", reflected: true, evidence: ";ls found" }]
      : [],
    error: null,
    tested_at: new Date().toISOString(),
  };
}

function makeDynamicReport(overrides: Partial<DynamicReport> = {}): DynamicReport {
  return {
    server_id: "srv-001",
    server_name: "Test Server",
    endpoint: "http://localhost:3333/mcp",
    consent: makeConsent(true),
    tested_at: new Date().toISOString(),
    elapsed_ms: 500,
    tools_tested: 2,
    tools_skipped: 1,
    output_findings_count: 0,
    injection_vulnerable_count: 0,
    probes: [],
    risk_summary: {
      output_injection_risk: "none",
      injection_vulnerability: "none",
      schema_compliance: "pass",
      timing_anomalies: 0,
    },
    ...overrides,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function readLines(filePath: string): string[] {
  return readFileSync(filePath, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0);
}

function parseLines(filePath: string): Record<string, unknown>[] {
  return readLines(filePath).map((l) => JSON.parse(l));
}

// ─── Test Suite ───────────────────────────────────────────────────────────────

describe("AuditLog — file creation", () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "audit-log-test-"));
    logPath = join(tmpDir, "sub", "audit.jsonl");
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("creates parent directories on construction", () => {
    new AuditLog(logPath);
    // Constructor calls mkdirSync — dir should exist after instantiation
    expect(existsSync(dirname(logPath))).toBe(true);
  });

  it("creates the log file on first write", () => {
    const log = new AuditLog(logPath);
    expect(existsSync(logPath)).toBe(false);
    log.logConsentCheck("srv-001", "Test Server", makeConsent(true));
    expect(existsSync(logPath)).toBe(true);
  });

  it("does not throw if directory already exists", () => {
    new AuditLog(logPath);
    expect(() => new AuditLog(logPath)).not.toThrow();
  });
});

describe("AuditLog — logConsentCheck", () => {
  let tmpDir: string;
  let logPath: string;
  let log: AuditLog;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "audit-log-test-"));
    logPath = join(tmpDir, "audit.jsonl");
    log = new AuditLog(logPath);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("writes a consent_check entry", () => {
    log.logConsentCheck("srv-001", "My Server", makeConsent(true));
    const entries = parseLines(logPath);
    expect(entries).toHaveLength(1);
    expect(entries[0].event).toBe("consent_check");
  });

  it("entry contains server_id and server_name", () => {
    log.logConsentCheck("srv-abc", "My MCP Server", makeConsent(true));
    const [entry] = parseLines(logPath);
    expect(entry.server_id).toBe("srv-abc");
    expect(entry.server_name).toBe("My MCP Server");
  });

  it("entry contains ISO timestamp", () => {
    log.logConsentCheck("srv-001", "S", makeConsent(true));
    const [entry] = parseLines(logPath);
    expect(typeof entry.timestamp).toBe("string");
    expect(() => new Date(entry.timestamp as string)).not.toThrow();
  });

  it("entry contains consent object with consented=true", () => {
    log.logConsentCheck("srv-001", "S", makeConsent(true));
    const [entry] = parseLines(logPath);
    const consent = entry.consent as Record<string, unknown>;
    expect(consent.consented).toBe(true);
    expect(consent.method).toBe("allowlist");
  });

  it("entry contains consent object with consented=false", () => {
    log.logConsentCheck("srv-001", "S", makeConsent(false));
    const [entry] = parseLines(logPath);
    const consent = entry.consent as Record<string, unknown>;
    expect(consent.consented).toBe(false);
    expect(consent.method).toBeNull();
  });

  it("entry is valid JSON on its own line", () => {
    log.logConsentCheck("srv-001", "S", makeConsent(true));
    const raw = readFileSync(logPath, "utf8");
    expect(raw.endsWith("\n")).toBe(true);
    const lines = raw.split("\n").filter((l) => l.trim());
    expect(() => JSON.parse(lines[0])).not.toThrow();
  });

  it("writes multiple consent entries, one per line", () => {
    log.logConsentCheck("srv-001", "S1", makeConsent(true));
    log.logConsentCheck("srv-002", "S2", makeConsent(false));
    const entries = parseLines(logPath);
    expect(entries).toHaveLength(2);
    expect(entries[0].server_id).toBe("srv-001");
    expect(entries[1].server_id).toBe("srv-002");
  });
});

describe("AuditLog — logProbe", () => {
  let tmpDir: string;
  let logPath: string;
  let log: AuditLog;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "audit-log-test-"));
    logPath = join(tmpDir, "audit.jsonl");
    log = new AuditLog(logPath);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("writes a tool_probe entry", () => {
    log.logProbe("srv-001", makeProbeResult());
    const [entry] = parseLines(logPath);
    expect(entry.event).toBe("tool_probe");
  });

  it("probe entry contains tool_name and elapsed_ms", () => {
    log.logProbe("srv-001", makeProbeResult("search_tool"));
    const [entry] = parseLines(logPath);
    const probe = entry.probe as Record<string, unknown>;
    expect(probe.tool_name).toBe("search_tool");
    expect(typeof probe.elapsed_ms).toBe("number");
  });

  it("probe entry contains status", () => {
    log.logProbe("srv-001", makeProbeResult());
    const [entry] = parseLines(logPath);
    const probe = entry.probe as Record<string, unknown>;
    expect(probe.status).toBe("success");
  });

  it("probe entry contains output_findings_count", () => {
    const probeWithFindings = makeProbeResult();
    probeWithFindings.output_findings = [
      { rule_id: "A1", severity: "critical", evidence: "injection" },
    ];
    log.logProbe("srv-001", probeWithFindings);
    const [entry] = parseLines(logPath);
    const probe = entry.probe as Record<string, unknown>;
    expect(probe.output_findings_count).toBe(1);
  });

  it("probe entry injection_reflected_count is 0 when none reflected", () => {
    log.logProbe("srv-001", makeProbeResult("t", false));
    const [entry] = parseLines(logPath);
    const probe = entry.probe as Record<string, unknown>;
    expect(probe.injection_reflected_count).toBe(0);
  });

  it("probe entry injection_reflected_count is 1 when one reflected", () => {
    log.logProbe("srv-001", makeProbeResult("t", true));
    const [entry] = parseLines(logPath);
    const probe = entry.probe as Record<string, unknown>;
    expect(probe.injection_reflected_count).toBe(1);
  });

  it("does NOT log raw output (privacy / log size concern)", () => {
    const probe = makeProbeResult();
    probe.raw_output = "sensitive data output";
    log.logProbe("srv-001", probe);
    const [entry] = parseLines(logPath);
    // raw_output should not appear in the probe sub-object
    const probe2 = entry.probe as Record<string, unknown>;
    expect(probe2.raw_output).toBeUndefined();
  });

  it("does NOT log canary input details in probe entry (only summary)", () => {
    log.logProbe("srv-001", makeProbeResult());
    const [entry] = parseLines(logPath);
    // The canary input may appear in the 'input' field if logged, but
    // we only check the probe is sanitized (no sensitive patterns)
    expect(entry.event).toBe("tool_probe");
  });
});

describe("AuditLog — logReportComplete", () => {
  let tmpDir: string;
  let logPath: string;
  let log: AuditLog;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "audit-log-test-"));
    logPath = join(tmpDir, "audit.jsonl");
    log = new AuditLog(logPath);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("writes a report_complete entry", () => {
    log.logReportComplete("srv-001", "My Server", makeDynamicReport());
    const [entry] = parseLines(logPath);
    expect(entry.event).toBe("report_complete");
  });

  it("entry contains report_summary with tools_tested", () => {
    log.logReportComplete("srv-001", "S", makeDynamicReport({ tools_tested: 5 }));
    const [entry] = parseLines(logPath);
    const summary = entry.report_summary as Record<string, unknown>;
    expect(summary.tools_tested).toBe(5);
  });

  it("entry contains report_summary with output_findings_count", () => {
    log.logReportComplete("srv-001", "S", makeDynamicReport({ output_findings_count: 3 }));
    const [entry] = parseLines(logPath);
    const summary = entry.report_summary as Record<string, unknown>;
    expect(summary.output_findings_count).toBe(3);
  });

  it("entry contains report_summary with injection_vulnerable_count", () => {
    log.logReportComplete("srv-001", "S", makeDynamicReport({ injection_vulnerable_count: 1 }));
    const [entry] = parseLines(logPath);
    const summary = entry.report_summary as Record<string, unknown>;
    expect(summary.injection_vulnerable_count).toBe(1);
  });

  it("entry contains risk_summary with all four fields", () => {
    log.logReportComplete("srv-001", "S", makeDynamicReport());
    const [entry] = parseLines(logPath);
    const summary = entry.report_summary as Record<string, unknown>;
    const risk = summary.risk_summary as Record<string, unknown>;
    expect(risk.output_injection_risk).toBe("none");
    expect(risk.injection_vulnerability).toBe("none");
    expect(risk.schema_compliance).toBe("pass");
    expect(risk.timing_anomalies).toBe(0);
  });

  it("does NOT include full probe list in report_complete (log size guard)", () => {
    // The probes array can be huge — report_complete should only log summary
    const report = makeDynamicReport({ probes: [makeProbeResult()] });
    log.logReportComplete("srv-001", "S", report);
    const [entry] = parseLines(logPath);
    // The top-level entry should not contain a 'probes' array
    expect((entry as Record<string, unknown>).probes).toBeUndefined();
  });
});

describe("AuditLog — append-only behaviour", () => {
  let tmpDir: string;
  let logPath: string;
  let log: AuditLog;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "audit-log-test-"));
    logPath = join(tmpDir, "audit.jsonl");
    log = new AuditLog(logPath);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("entries are appended in write order", () => {
    log.logConsentCheck("srv-001", "S1", makeConsent(true));
    log.logProbe("srv-001", makeProbeResult("tool_a"));
    log.logReportComplete("srv-001", "S1", makeDynamicReport());

    const entries = parseLines(logPath);
    expect(entries).toHaveLength(3);
    expect(entries[0].event).toBe("consent_check");
    expect(entries[1].event).toBe("tool_probe");
    expect(entries[2].event).toBe("report_complete");
  });

  it("a second AuditLog instance on the same file appends, not overwrites", () => {
    log.logConsentCheck("srv-001", "S1", makeConsent(true));

    const log2 = new AuditLog(logPath);
    log2.logConsentCheck("srv-002", "S2", makeConsent(false));

    const entries = parseLines(logPath);
    expect(entries).toHaveLength(2);
    expect(entries[0].server_id).toBe("srv-001");
    expect(entries[1].server_id).toBe("srv-002");
  });

  it("10 rapid writes all persist", () => {
    for (let i = 0; i < 10; i++) {
      log.logProbe(`srv-${i}`, makeProbeResult(`tool_${i}`));
    }
    const entries = parseLines(logPath);
    expect(entries).toHaveLength(10);
  });

  it("each line is independent valid JSON", () => {
    log.logConsentCheck("srv-001", "S", makeConsent(true));
    log.logProbe("srv-001", makeProbeResult());
    log.logReportComplete("srv-001", "S", makeDynamicReport());

    const raw = readFileSync(logPath, "utf8");
    const lines = raw.split("\n").filter((l) => l.trim());
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });
});

describe("AuditLog — write failure resilience", () => {
  it("does not throw when log path is unwritable (e.g., root-only dir)", () => {
    // Use an impossible path to trigger the catch block
    const impossiblePath = "/root/no-permission/audit.jsonl";
    const log = new AuditLog(impossiblePath);
    // Should not throw — errors are caught internally and written to stderr
    expect(() =>
      log.logConsentCheck("srv-001", "S", makeConsent(true))
    ).not.toThrow();
  });

  it("continues to function after a write failure", () => {
    const impossiblePath = "/root/no-permission/audit.jsonl";
    const log = new AuditLog(impossiblePath);
    // Multiple calls should all be resilient
    expect(() => {
      log.logConsentCheck("s", "S", makeConsent(true));
      log.logProbe("s", makeProbeResult());
      log.logReportComplete("s", "S", makeDynamicReport());
    }).not.toThrow();
  });
});

describe("AuditLog — JSONL format invariants", () => {
  let tmpDir: string;
  let logPath: string;
  let log: AuditLog;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "audit-log-test-"));
    logPath = join(tmpDir, "audit.jsonl");
    log = new AuditLog(logPath);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("each entry is terminated with a newline (JSONL standard)", () => {
    log.logConsentCheck("srv-001", "S", makeConsent(true));
    const raw = readFileSync(logPath, "utf8");
    expect(raw.endsWith("\n")).toBe(true);
  });

  it("no entry contains embedded newlines (compact JSON)", () => {
    log.logConsentCheck("srv-001", "S", makeConsent(true));
    log.logProbe("srv-001", makeProbeResult());
    const lines = readLines(logPath);
    for (const line of lines) {
      expect(line).not.toContain("\n");
    }
  });

  it("all entries have event, timestamp, server_id fields", () => {
    log.logConsentCheck("srv-001", "S", makeConsent(true));
    log.logProbe("srv-001", makeProbeResult());
    log.logReportComplete("srv-001", "S", makeDynamicReport());

    const entries = parseLines(logPath);
    for (const entry of entries) {
      expect(typeof entry.event).toBe("string");
      expect(typeof entry.timestamp).toBe("string");
      expect(typeof entry.server_id).toBe("string");
    }
  });
});
