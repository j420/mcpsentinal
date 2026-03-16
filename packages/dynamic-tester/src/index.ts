/**
 * Dynamic Tester — gated tool invocation engine.
 *
 * IMPORTANT: This module ONLY runs against servers that have explicitly
 * opted in via one of three consent mechanisms. See consent.ts.
 *
 * Usage:
 *   const tester = new DynamicTester({ allowlist: ['server-uuid-123'] });
 *   const report = await tester.test(server, endpoint, tools);
 *
 * The report contains:
 *   - Consent record (how/when consent was obtained)
 *   - Per-tool probe results (canary input → output → findings)
 *   - Injection probe results (reflection detection)
 *   - Aggregate risk summary
 *   - Full audit trail written to disk
 */
import { checkConsent } from "./consent.js";
import { generateCanaryInput, getInjectionPayloads } from "./canary.js";
import { scanToolOutput, assessOutputRisk, detectReflection } from "./output-scanner.js";
import { AuditLog } from "./audit-log.js";
import type {
  DynamicReport,
  DynamicTesterConfig,
  ProbeResult,
  ConsentResult,
} from "./types.js";
import { DEFAULT_CONFIG } from "./types.js";

export { DynamicTester };
export type {
  DynamicReport,
  DynamicTesterConfig,
  ProbeResult,
  ConsentResult,
};
export { checkConsent } from "./consent.js";
export { generateCanaryInput, getInjectionPayloads } from "./canary.js";
export { scanToolOutput, assessOutputRisk } from "./output-scanner.js";

interface ServerInfo {
  id: string;
  name: string;
}

interface ToolInfo {
  name: string;
  description: string | null;
  input_schema: Record<string, unknown> | null;
}

class DynamicTester {
  private config: Required<DynamicTesterConfig>;
  private auditLog: AuditLog;

  constructor(config: DynamicTesterConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.auditLog = new AuditLog(this.config.audit_log_path);
  }

  /**
   * Run dynamic testing against a server.
   *
   * @param server - Server identity (id + name)
   * @param endpoint - The server's MCP endpoint URL
   * @param tools - Tools enumerated during the connection stage
   * @param callTool - Function that actually invokes a tool (provided by caller to avoid SDK coupling)
   */
  async test(
    server: ServerInfo,
    endpoint: string,
    tools: ToolInfo[],
    callTool: (toolName: string, input: Record<string, unknown>) => Promise<string>
  ): Promise<DynamicReport> {
    const startedAt = Date.now();

    // ── Step 1: Consent check ──────────────────────────────────────────────
    const consent = await checkConsent(server.id, endpoint, tools, {
      allowlist: this.config.allowlist,
    });

    this.auditLog.logConsentCheck(server.id, server.name, consent);

    if (!consent.consented) {
      return this.buildDeniedReport(server, endpoint, consent, startedAt);
    }

    // ── Step 2: Filter tools ────────────────────────────────────────────────
    const eligibleTools = tools
      .filter((t) => !this.isBlocklisted(t.name))
      .slice(0, this.config.max_tools_per_server);

    const skippedCount = tools.length - eligibleTools.length;

    // ── Step 3: Probe each tool ─────────────────────────────────────────────
    const probes: ProbeResult[] = [];

    for (const tool of eligibleTools) {
      const probe = await this.probeOneTool(server.id, tool, callTool);
      this.auditLog.logProbe(server.id, probe);
      probes.push(probe);
    }

    // ── Step 4: Aggregate risk ──────────────────────────────────────────────
    const allOutputFindings = probes.flatMap((p) => p.output_findings);
    const injectionVulnCount = probes.reduce(
      (s, p) => s + p.injection_probes.filter((ip) => ip.reflected).length,
      0
    );
    const timingAnomalies = probes.filter(
      (p) => p.response_time_ms > 10_000
    ).length;

    const outputRisk = assessOutputRisk(allOutputFindings);
    const injectionRisk = riskFromCount(injectionVulnCount);
    const schemaCompliance = probes.every((p) => p.status === "success" || p.status === "error")
      ? "pass"
      : probes.some((p) => p.status === "timeout")
        ? "warn"
        : "fail";

    const report: DynamicReport = {
      server_id: server.id,
      server_name: server.name,
      endpoint,
      consent,
      tested_at: new Date().toISOString(),
      elapsed_ms: Date.now() - startedAt,
      tools_tested: probes.length,
      tools_skipped: skippedCount,
      output_findings_count: allOutputFindings.length,
      injection_vulnerable_count: injectionVulnCount,
      probes,
      risk_summary: {
        output_injection_risk: outputRisk,
        injection_vulnerability: injectionRisk,
        schema_compliance: schemaCompliance,
        timing_anomalies: timingAnomalies,
      },
    };

    this.auditLog.logReportComplete(server.id, server.name, report);
    return report;
  }

  private async probeOneTool(
    serverId: string,
    tool: ToolInfo,
    callTool: (name: string, input: Record<string, unknown>) => Promise<string>
  ): Promise<ProbeResult> {
    const canary = generateCanaryInput(tool.name, tool.input_schema);
    const startedAt = Date.now();

    let rawOutput: string | null = null;
    let status: ProbeResult["status"] = "success";
    let error: string | null = null;

    try {
      rawOutput = await Promise.race([
        callTool(tool.name, canary.input),
        new Promise<never>((_, reject) =>
          setTimeout(
            () => reject(new Error("timeout")),
            this.config.tool_timeout_ms
          )
        ),
      ]);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg === "timeout") {
        status = "timeout";
      } else {
        status = "error";
        error = msg;
      }
    }

    const elapsed = Date.now() - startedAt;

    // Scan output for injection payloads
    const outputFindings = rawOutput
      ? scanToolOutput(tool.name, rawOutput, serverId)
      : [];

    // Run injection probes if enabled
    const injectionProbes: ProbeResult["injection_probes"] = [];

    if (this.config.enable_injection_probes && tool.input_schema?.properties) {
      const properties = tool.input_schema.properties as Record<string, unknown>;
      for (const paramName of Object.keys(properties)) {
        const payloads = getInjectionPayloads(paramName);

        for (const payload of payloads) {
          let probeOutput = "";
          try {
            const probeInput = { ...canary.input, [paramName]: payload.value };
            probeOutput = await Promise.race([
              callTool(tool.name, probeInput),
              new Promise<never>((_, reject) =>
                setTimeout(() => reject(new Error("timeout")), 5_000)
              ),
            ]);
          } catch {
            // Probe timeout or error — not reflected
          }

          const reflected = detectReflection(probeOutput, payload.canary_token);
          injectionProbes.push({
            probe_type: payload.type,
            payload: payload.value,
            reflected,
            evidence: reflected ? probeOutput.slice(0, 500) : null,
          });
        }
      }
    }

    return {
      tool_name: tool.name,
      status,
      canary_input: canary.input,
      raw_output: rawOutput,
      response_time_ms: elapsed,
      output_findings: outputFindings,
      injection_probes: injectionProbes,
      error,
      tested_at: new Date().toISOString(),
    };
  }

  private isBlocklisted(toolName: string): boolean {
    return this.config.blocklist_tool_patterns.some((pattern) => pattern.test(toolName));
  }

  private buildDeniedReport(
    server: ServerInfo,
    endpoint: string,
    consent: ConsentResult,
    startedAt: number
  ): DynamicReport {
    return {
      server_id: server.id,
      server_name: server.name,
      endpoint,
      consent,
      tested_at: new Date().toISOString(),
      elapsed_ms: Date.now() - startedAt,
      tools_tested: 0,
      tools_skipped: 0,
      output_findings_count: 0,
      injection_vulnerable_count: 0,
      probes: [],
      risk_summary: {
        output_injection_risk: "none",
        injection_vulnerability: "none",
        schema_compliance: "pass",
        timing_anomalies: 0,
      },
    };
  }
}

function riskFromCount(n: number): DynamicReport["risk_summary"]["injection_vulnerability"] {
  if (n === 0) return "none";
  if (n <= 1) return "low";
  if (n <= 3) return "medium";
  if (n <= 6) return "high";
  return "critical";
}
