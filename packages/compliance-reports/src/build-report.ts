import type { Severity } from "@mcp-sentinel/database";

import { getFramework } from "./frameworks/index.js";
import type { FrameworkControl } from "./frameworks/types.js";
import type {
  ComplianceReport,
  ConfidenceBand,
  ControlEvidence,
  ControlResult,
  ControlStatus,
  FrameworkId,
  KillChainNarrative,
  OverallStatus,
  ReportInputFinding,
  ReportServer,
  ReportSummary,
} from "./types.js";

export interface BuildReportInput {
  framework_id: FrameworkId;
  server: ReportServer;
  findings: ReportInputFinding[];
  coverage: {
    band: ConfidenceBand;
    ratio: number;
    techniques_run: string[];
  };
  rules_version: string;
  sentinel_version: string;
  /** Kill chains from packages/attack-graph. Empty array is valid — Phase 5.3 fills this. */
  kill_chains: KillChainNarrative[];
  /** Overrideable for deterministic test output. Defaults to current wall clock. */
  assessed_at?: string;
}

/** Severity ordering used for threshold comparisons. */
const SEVERITY_RANK: Record<Severity, number> = {
  informational: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

const EVIDENCE_SUMMARY_MAX_CHARS = 200;
const MAX_MITIGATIONS_PER_CONTROL = 5;

export function buildReport(input: BuildReportInput): ComplianceReport {
  const framework = getFramework(input.framework_id);
  // Pre-index findings by rule_id so control-level lookup is O(1) per control.
  const findingsByRule = indexFindingsByRule(input.findings);

  const controls: ControlResult[] = framework.controls.map((c) =>
    evaluateControl(c, findingsByRule),
  );
  const summary = summarize(controls);

  return {
    version: "1.0",
    server: input.server,
    framework: {
      id: framework.id,
      name: framework.name,
      version: framework.version,
      last_updated: framework.last_updated,
      source_url: framework.source_url,
    },
    assessment: {
      assessed_at: input.assessed_at ?? new Date().toISOString(),
      rules_version: input.rules_version,
      sentinel_version: input.sentinel_version,
      coverage_band: input.coverage.band,
      coverage_ratio: input.coverage.ratio,
      techniques_run: [...input.coverage.techniques_run],
    },
    controls,
    summary,
    kill_chains: input.kill_chains,
    executive_summary: buildExecutiveSummary(input.server, framework.name, summary),
  };
}

function indexFindingsByRule(findings: ReportInputFinding[]): Map<string, ReportInputFinding[]> {
  const m = new Map<string, ReportInputFinding[]>();
  for (const f of findings) {
    let bucket = m.get(f.rule_id);
    if (!bucket) {
      bucket = [];
      m.set(f.rule_id, bucket);
    }
    bucket.push(f);
  }
  return m;
}

function evaluateControl(
  control: FrameworkControl,
  findingsByRule: Map<string, ReportInputFinding[]>,
): ControlResult {
  if (control.assessor_rule_ids.length === 0) {
    // Honest gap — see per-framework NO ASSESSOR RULE comments.
    return {
      control_id: control.control_id,
      control_name: control.control_name,
      control_description: control.control_description,
      source_url: control.source_url,
      status: "not_applicable",
      evidence: [],
      rationale: "No MCP Sentinel assessor rule is mapped to this control. Status is not_applicable pending Phase 6 coverage expansion.",
      required_mitigations: [],
      assessor_rule_ids: [],
    };
  }

  const evidence: ControlEvidence[] = [];
  for (const ruleId of control.assessor_rule_ids) {
    const ruleFindings = findingsByRule.get(ruleId);
    if (!ruleFindings) continue;
    for (const f of ruleFindings) {
      evidence.push({
        finding_id: f.id,
        rule_id: f.rule_id,
        severity: f.severity,
        evidence_summary: f.evidence.slice(0, EVIDENCE_SUMMARY_MAX_CHARS),
        confidence: f.confidence,
      });
    }
  }

  const status = deriveStatus(control, evidence);
  const rationale = buildRationale(control, evidence, status);
  const required_mitigations = deriveMitigations(control, findingsByRule);

  return {
    control_id: control.control_id,
    control_name: control.control_name,
    control_description: control.control_description,
    source_url: control.source_url,
    status,
    evidence,
    rationale,
    required_mitigations,
    assessor_rule_ids: [...control.assessor_rule_ids],
  };
}

function deriveStatus(control: FrameworkControl, evidence: ControlEvidence[]): ControlStatus {
  if (evidence.length === 0) return "met";
  const threshold = SEVERITY_RANK[control.unmet_threshold];
  const anyAbove = evidence.some((e) => SEVERITY_RANK[e.severity] >= threshold);
  return anyAbove ? "unmet" : "partial";
}

function buildRationale(
  control: FrameworkControl,
  evidence: ControlEvidence[],
  status: ControlStatus,
): string {
  const assessors = control.assessor_rule_ids.length;
  if (evidence.length === 0) {
    return `${assessors} assessor rule(s) evaluated this control; no findings observed.`;
  }
  const bySeverity: Record<string, number> = {};
  for (const e of evidence) {
    bySeverity[e.severity] = (bySeverity[e.severity] ?? 0) + 1;
  }
  const breakdown = Object.entries(bySeverity)
    .map(([sev, n]) => `${n} ${sev}`)
    .join(", ");
  const statusLine =
    status === "unmet"
      ? `at least one finding is at or above the ${control.unmet_threshold} threshold (status: unmet)`
      : `all findings are below the ${control.unmet_threshold} threshold (status: partial)`;
  return `${assessors} assessor rule(s) evaluated this control; ${evidence.length} finding(s) observed (${breakdown}); ${statusLine}.`;
}

function deriveMitigations(
  control: FrameworkControl,
  findingsByRule: Map<string, ReportInputFinding[]>,
): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const ruleId of control.assessor_rule_ids) {
    const ruleFindings = findingsByRule.get(ruleId);
    if (!ruleFindings) continue;
    for (const f of ruleFindings) {
      const r = f.remediation.trim();
      if (!r || seen.has(r)) continue;
      seen.add(r);
      out.push(r);
      if (out.length >= MAX_MITIGATIONS_PER_CONTROL) return out;
    }
  }
  return out;
}

function summarize(controls: ControlResult[]): ReportSummary {
  let met = 0;
  let unmet = 0;
  let partial = 0;
  let na = 0;
  for (const c of controls) {
    switch (c.status) {
      case "met": met++; break;
      case "unmet": unmet++; break;
      case "partial": partial++; break;
      case "not_applicable": na++; break;
    }
  }
  return {
    total_controls: controls.length,
    met,
    unmet,
    partial,
    not_applicable: na,
    overall_status: deriveOverallStatus(controls.length, met, unmet, partial, na),
  };
}

function deriveOverallStatus(
  total: number,
  met: number,
  unmet: number,
  partial: number,
  na: number,
): OverallStatus {
  if (unmet > 0) return "non_compliant";
  if (partial > 0) return "partially_compliant";
  // A framework where every scoped control is met, with N/A only for
  // documented gaps, still counts as compliant on the covered surface.
  if (met > 0 && met + na === total) return "compliant";
  // All controls are N/A — we literally could not assess this server on
  // this framework. Explicitly distinct from "compliant" to avoid
  // misleading regulators.
  return "insufficient_evidence";
}

function buildExecutiveSummary(
  server: ReportServer,
  frameworkName: string,
  summary: ReportSummary,
): string {
  const assessed = summary.total_controls - summary.not_applicable;
  const header = `Assessment of ${server.name} against ${frameworkName}: overall status ${summary.overall_status.replace(/_/g, " ")}.`;
  const counts = `Of ${summary.total_controls} controls, ${summary.met} met, ${summary.unmet} unmet, ${summary.partial} partial, ${summary.not_applicable} not applicable.`;
  const scope = `${assessed} control(s) fell within MCP Sentinel's current assessor coverage; remaining control(s) are documented as not_applicable until Phase 6 expands coverage.`;
  const focus =
    summary.unmet > 0
      ? "Unmet controls have findings at or above the framework's mandatory severity threshold and should be remediated before relying on this server in a regulated deployment."
      : summary.partial > 0
        ? "No control is unmet, but partial findings indicate residual risk below the mandatory threshold."
        : "No findings were observed on the covered control surface.";
  const provenance = `All claims are traceable to individual finding rows via finding_id and to the governing rule via rule_id; the enclosing signed envelope commits MCP Sentinel to the exact bytes of this report.`;
  return [header, counts, scope, focus, provenance].join(" ");
}
