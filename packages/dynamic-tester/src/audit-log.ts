/**
 * Append-only audit log for dynamic tool invocations.
 *
 * Every tool call made during dynamic testing is recorded here.
 * This log is the legal/ethical paper trail — it proves that:
 *   - Consent was obtained before any tool was called
 *   - Only canary inputs were used (no real user data)
 *   - The exact tool, input, output, and timestamp are on record
 *
 * Format: newline-delimited JSON (JSONL) for streaming and easy grep.
 * File is append-only — never truncated, never overwritten.
 */
import { appendFileSync, mkdirSync } from "fs";
import { dirname } from "path";
import type { DynamicReport, ProbeResult, ConsentResult } from "./types.js";

export interface AuditEntry {
  event: "consent_check" | "tool_probe" | "report_complete";
  timestamp: string;
  server_id: string;
  server_name?: string;
  consent?: ConsentResult;
  probe?: {
    tool_name: string;
    input: Record<string, unknown>;
    status: string;
    output_findings_count: number;
    injection_reflected_count: number;
    elapsed_ms: number;
  };
  report_summary?: {
    tools_tested: number;
    output_findings_count: number;
    injection_vulnerable_count: number;
    risk_summary: DynamicReport["risk_summary"];
  };
}

export class AuditLog {
  private readonly path: string;

  constructor(logPath: string) {
    this.path = logPath;
    // Ensure parent directory exists
    try {
      mkdirSync(dirname(logPath), { recursive: true });
    } catch {
      // Directory may already exist
    }
  }

  logConsentCheck(serverId: string, serverName: string, consent: ConsentResult): void {
    this.append({
      event: "consent_check",
      timestamp: new Date().toISOString(),
      server_id: serverId,
      server_name: serverName,
      consent,
    });
  }

  logProbe(serverId: string, probe: ProbeResult): void {
    this.append({
      event: "tool_probe",
      timestamp: new Date().toISOString(),
      server_id: serverId,
      probe: {
        tool_name: probe.tool_name,
        input: probe.canary_input,
        status: probe.status,
        output_findings_count: probe.output_findings.length,
        injection_reflected_count: probe.injection_probes.filter((p) => p.reflected).length,
        elapsed_ms: probe.response_time_ms,
      },
    });
  }

  logReportComplete(serverId: string, serverName: string, report: DynamicReport): void {
    this.append({
      event: "report_complete",
      timestamp: new Date().toISOString(),
      server_id: serverId,
      server_name: serverName,
      report_summary: {
        tools_tested: report.tools_tested,
        output_findings_count: report.output_findings_count,
        injection_vulnerable_count: report.injection_vulnerable_count,
        risk_summary: report.risk_summary,
      },
    });
  }

  private append(entry: AuditEntry): void {
    try {
      appendFileSync(this.path, JSON.stringify(entry) + "\n", "utf8");
    } catch {
      // Audit log write failure should never crash the tester
      // Log to stderr instead
      process.stderr.write(
        `[audit-log] Failed to write to ${this.path}: ${JSON.stringify(entry)}\n`
      );
    }
  }
}
