/**
 * Compliance reporter — turns a `ComplianceScanResult` into a human
 * readable text report. Used by the CLI for stdout output and by tests
 * for snapshotting.
 */

import type {
  ComplianceFinding,
  ComplianceReport,
  ComplianceScanResult,
} from "./types.js";

export function renderTextReport(result: ComplianceScanResult): string {
  const lines: string[] = [];
  lines.push("# MCP Sentinel — Compliance Scan");
  lines.push("");
  lines.push(`Scan id: ${result.scan_id}`);
  lines.push(`Server : ${result.server_id}`);
  lines.push(`Duration: ${result.duration_ms} ms`);
  lines.push(
    `LLM calls: ${result.llm_calls_made} (cached: ${result.cached_runs})`,
  );
  lines.push(`Frameworks: ${result.reports.length}`);
  lines.push("");

  for (const report of result.reports) {
    lines.push(renderReport(report));
    lines.push("");
  }

  return lines.join("\n");
}

export function renderReport(report: ComplianceReport): string {
  const lines: string[] = [];
  lines.push(`## ${report.framework_metadata.name}`);
  lines.push(
    `Status: ${report.overall_status}   Score: ${report.compliance_score}/100   Findings: ${report.findings_count}`,
  );
  lines.push("");

  for (const cat of report.category_results) {
    const marker =
      cat.status === "compliant"
        ? "[OK]"
        : cat.status === "non-compliant"
          ? "[FAIL]"
          : cat.status === "partial"
            ? "[PARTIAL]"
            : "[N/A]";
    lines.push(`${marker} ${cat.category.name}  (${cat.category.control})`);
    if (cat.findings.length === 0) {
      lines.push(`    no findings`);
    } else {
      for (const f of cat.findings) {
        lines.push(formatFinding(f, "    "));
      }
    }
  }
  return lines.join("\n");
}

function formatFinding(f: ComplianceFinding, indent: string): string {
  const lines: string[] = [];
  lines.push(`${indent}- ${f.rule_id} (${f.severity}, confidence ${f.confidence.toFixed(2)})`);
  lines.push(`${indent}  test: ${f.test.hypothesis}`);
  lines.push(`${indent}  judge: ${f.judge_result.judge_rationale}`);
  lines.push(`${indent}  remediation: ${f.remediation}`);
  return lines.join("\n");
}
