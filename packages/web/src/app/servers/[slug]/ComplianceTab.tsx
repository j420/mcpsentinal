"use client";

/**
 * ComplianceTab — Public compliance panel for the server detail page.
 *
 * Fetches `${API_URL}/api/v1/servers/:slug/compliance` on mount and renders
 * judge-confirmed compliance findings grouped by framework → category →
 * rule. The endpoint NEVER returns `judge_rationale`, prompts, or LLM
 * response text (redacted server-side by `publicComplianceRow` in
 * `packages/api/src/server.ts`) — regulators replay via the private
 * `compliance_agent_runs` audit trail.
 *
 * Per the Phase 5 plan and locked user decisions, this component
 * deliberately does NOT render:
 *   - `judge_rationale` (not in API response)
 *   - confidence score (reserved for future)
 *   - any LLM narrative text
 *
 * What it DOES render:
 *   - severity badge
 *   - rule id + category/control id
 *   - test hypothesis (the adversarial claim being tested)
 *   - an evidence pointer summary (top-level keys of `evidence_chain`)
 *   - remediation
 *
 * Frameworks are listed in regulator-priority order: EU AI Act first
 * (August 2026 deadline), then MITRE ATLAS, then OWASP, CoSAI, MAESTRO.
 * Frameworks with zero findings render a "clean" state so users can tell
 * the difference between "not scanned" and "scanned, no violations".
 */

import React, { useEffect, useState } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

type FrameworkId =
  | "eu_ai_act"
  | "mitre_atlas"
  | "owasp_mcp"
  | "owasp_asi"
  | "cosai"
  | "maestro";

type Severity = "critical" | "high" | "medium" | "low" | "informational";

interface ComplianceRow {
  id: string;
  framework: FrameworkId;
  rule_id: string;
  category_control: string;
  severity: Severity;
  confidence: number;
  bundle_id: string;
  test_id: string;
  test_hypothesis: string;
  evidence_chain: Record<string, unknown>;
  remediation: string;
  created_at: string;
}

interface ComplianceResponse {
  data: Record<FrameworkId, ComplianceRow[]>;
  meta: {
    total_findings: number;
    frameworks_with_findings: number;
    last_scan_at: string | null;
  };
}

const FRAMEWORK_ORDER: FrameworkId[] = [
  "eu_ai_act",
  "mitre_atlas",
  "owasp_mcp",
  "owasp_asi",
  "cosai",
  "maestro",
];

const FRAMEWORK_LABELS: Record<FrameworkId, string> = {
  eu_ai_act: "EU AI Act",
  mitre_atlas: "MITRE ATLAS",
  owasp_mcp: "OWASP MCP Top 10",
  owasp_asi: "OWASP Agentic Top 10",
  cosai: "CoSAI MCP Security",
  maestro: "MAESTRO",
};

const FRAMEWORK_BLURBS: Record<FrameworkId, string> = {
  eu_ai_act:
    "EU AI Act — Articles 9, 12, 13, 14, 15 (high-risk AI system obligations).",
  mitre_atlas:
    "MITRE ATLAS — adversarial ML technique coverage (AML.T0054 family).",
  owasp_mcp: "OWASP MCP Top 10 — the canonical MCP-specific risk register.",
  owasp_asi:
    "OWASP Agentic Applications Top 10 (ASI01–ASI10) — agent-system risks.",
  cosai: "CoSAI MCP Security — industry consortium threat taxonomy (T1–T12).",
  maestro: "MAESTRO — seven-layer agentic AI security framework (L1–L7).",
};

function groupByCategory(rows: ComplianceRow[]): Map<string, ComplianceRow[]> {
  const byCat = new Map<string, ComplianceRow[]>();
  for (const row of rows) {
    const existing = byCat.get(row.category_control);
    if (existing) existing.push(row);
    else byCat.set(row.category_control, [row]);
  }
  return byCat;
}

function evidenceSummary(chain: Record<string, unknown>): string {
  const keys = Object.keys(chain);
  if (keys.length === 0) return "no structured evidence";
  return keys.slice(0, 6).join(" • ") + (keys.length > 6 ? ` • +${keys.length - 6}` : "");
}

interface Props {
  slug: string;
}

export default function ComplianceTab({ slug }: Props) {
  const [state, setState] = useState<
    | { kind: "loading" }
    | { kind: "error"; message: string }
    | { kind: "ready"; payload: ComplianceResponse }
  >({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      try {
        const res = await fetch(
          `${API_URL}/api/v1/servers/${encodeURIComponent(slug)}/compliance`,
          { signal: AbortSignal.timeout(6000) }
        );
        if (!res.ok) {
          if (cancelled) return;
          setState({
            kind: "error",
            message: `API returned ${res.status}`,
          });
          return;
        }
        const payload = (await res.json()) as ComplianceResponse;
        if (cancelled) return;
        setState({ kind: "ready", payload });
      } catch (err) {
        if (cancelled) return;
        setState({
          kind: "error",
          message: err instanceof Error ? err.message : "Unknown error",
        });
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [slug]);

  if (state.kind === "loading") {
    return (
      <section className="sd-section" aria-busy="true">
        <h2 className="sd-section-title">Compliance</h2>
        <p className="sd-section-sub">Loading compliance findings…</p>
      </section>
    );
  }

  if (state.kind === "error") {
    return (
      <section className="sd-section">
        <h2 className="sd-section-title">Compliance</h2>
        <p className="sd-section-sub">
          Unable to load compliance findings ({state.message}). This does
          <strong> not</strong> mean the server is compliant — it means the
          compliance API is unreachable right now.
        </p>
      </section>
    );
  }

  const { data, meta } = state.payload;

  if (meta.total_findings === 0) {
    return (
      <section className="sd-section">
        <h2 className="sd-section-title">Compliance</h2>
        <p className="sd-section-sub">
          No compliance violations detected across all six frameworks. If
          this server has never been scanned by the compliance agents,
          nothing will be shown here even though the section renders.
        </p>
        <div className="sd-owasp-grid">
          {FRAMEWORK_ORDER.map((fw) => (
            <div
              key={fw}
              className="sd-owasp-item sd-owasp-clean"
            >
              <span className="sd-owasp-indicator" />
              <span className="sd-owasp-id">{FRAMEWORK_LABELS[fw]}</span>
              <span className="sd-owasp-status">No findings</span>
            </div>
          ))}
        </div>
      </section>
    );
  }

  return (
    <section className="sd-section">
      <h2 className="sd-section-title">
        Compliance
        <span className="sd-section-count">{meta.total_findings}</span>
      </h2>
      <p className="sd-section-sub">
        {meta.total_findings} judge-confirmed finding
        {meta.total_findings !== 1 ? "s" : ""} across{" "}
        {meta.frameworks_with_findings} of 6 frameworks. Only findings that
        passed the deterministic judge are shown — the LLM reasoning trail
        is kept private for regulator replay.
      </p>

      {FRAMEWORK_ORDER.map((fw) => {
        const rows = data[fw] ?? [];
        if (rows.length === 0) {
          return (
            <details key={fw} className="sd-compliance-framework">
              <summary className="sd-compliance-framework-summary sd-compliance-clean">
                <span className="sd-compliance-framework-name">
                  {FRAMEWORK_LABELS[fw]}
                </span>
                <span className="sd-compliance-framework-count">
                  No findings
                </span>
              </summary>
              <p className="sd-section-sub">{FRAMEWORK_BLURBS[fw]}</p>
            </details>
          );
        }

        const byCategory = groupByCategory(rows);

        return (
          <details key={fw} className="sd-compliance-framework" open>
            <summary className="sd-compliance-framework-summary">
              <span className="sd-compliance-framework-name">
                {FRAMEWORK_LABELS[fw]}
              </span>
              <span className="sd-compliance-framework-count">
                {rows.length} finding{rows.length !== 1 ? "s" : ""}
              </span>
            </summary>
            <p className="sd-section-sub">{FRAMEWORK_BLURBS[fw]}</p>

            {Array.from(byCategory.entries()).map(([category, catRows]) => (
              <div key={category} className="sd-compliance-category">
                <h3 className="sd-compliance-category-title">
                  {category}
                  <span className="sd-section-count">{catRows.length}</span>
                </h3>
                <div className="sd-findings-list">
                  {catRows.map((row) => (
                    <div
                      key={row.id}
                      className={`sd-finding-card sd-finding-${row.severity}`}
                    >
                      <div className="sd-finding-header">
                        <span className={`sev-badge sev-${row.severity}`}>
                          {row.severity}
                        </span>
                        <span className="sd-finding-rule-id">
                          {row.rule_id}
                        </span>
                        <span className="sd-finding-rule-name">
                          {row.test_hypothesis || row.test_id}
                        </span>
                        <span className="sd-finding-tag sd-finding-owasp">
                          {row.category_control}
                        </span>
                      </div>
                      <div className="sd-finding-evidence">
                        <strong>Evidence pointers:</strong>{" "}
                        {evidenceSummary(row.evidence_chain)}
                      </div>
                      {row.remediation && (
                        <div className="sd-finding-remediation">
                          <strong>Remediation:</strong> {row.remediation}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </details>
        );
      })}
    </section>
  );
}
