import React from "react";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Attack Chains | MCP Sentinel",
  description:
    "Multi-step kill chains detected across MCP server configurations. CVE-backed attack chain synthesis with exploitability scoring.",
};

export const dynamic = "force-dynamic";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

// ── Types ─────────────────────────────────────────────────────────────────────

interface AttackChainSummary {
  id: string;
  chain_id: string;
  config_id: string;
  kill_chain_id: string;
  kill_chain_name: string;
  steps: Array<{
    ordinal: number;
    server_id: string;
    server_name: string;
    role: string;
  }>;
  exploitability_overall: number;
  exploitability_rating: "critical" | "high" | "medium" | "low";
  narrative: string;
  owasp_refs: string[];
  mitre_refs: string[];
  mitigations: Array<{
    action: string;
    target_server_name: string;
    effect: string;
  }>;
  created_at: string;
}

// ── Data ──────────────────────────────────────────────────────────────────────

async function getAttackChains(): Promise<AttackChainSummary[]> {
  try {
    const res = await fetch(`${API_URL}/api/v1/attack-chains`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.data ?? [];
  } catch {
    return [];
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const RATING_LABELS: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

const KC_PRECEDENTS: Record<string, string> = {
  KC01: "Claude Desktop 2024-Q4",
  KC02: "CVE-2025-54135",
  KC03: "Wiz Research 2025",
  KC04: "Invariant Labs Jan 2026",
  KC05: "Trail of Bits Feb 2026",
  KC06: "DNS exfiltration research",
  KC07: "DB privesc via MCP 2025",
};

const KC_OBJECTIVES: Record<string, string> = {
  KC01: "Data Exfiltration",
  KC02: "Remote Code Execution",
  KC03: "Credential Theft",
  KC04: "Persistent Backdoor",
  KC05: "Remote Code Execution",
  KC06: "Data Exfiltration",
  KC07: "Privilege Escalation",
};

const ROLE_LABELS: Record<string, string> = {
  injection_gateway: "Entry Point",
  pivot: "Pivot",
  data_source: "Data Source",
  executor: "Executor",
  exfiltrator: "Exfiltrator",
  config_writer: "Config Writer",
  memory_writer: "Memory Writer",
};

function fmtDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function fmtPct(n: number): string {
  return `${(n * 100).toFixed(0)}%`;
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default async function AttackChainsPage() {
  const chains = await getAttackChains();

  return (
    <div className="ac-page">
      <nav className="sd-breadcrumb">
        <a href="/">Home</a>
        <span className="sd-bread-sep">/</span>
        <span className="sd-bread-current">Attack Chains</span>
      </nav>

      <section className="ac-hero">
        <h1 className="ac-hero-title">Kill Chain Analysis</h1>
        <p className="ac-hero-desc">
          Multi-step attack chains detected across MCP server configurations.
          Each chain is backed by a real-world CVE or published security research.
          7 kill chain templates (KC01&ndash;KC07) with 7-factor exploitability scoring.
        </p>
        <div className="ac-hero-stats">
          <div className="ac-hero-stat">
            <span className="ac-hero-stat-val">{chains.length}</span>
            <span className="ac-hero-stat-label">Chains Detected</span>
          </div>
          <div className="ac-hero-stat">
            <span className="ac-hero-stat-val" style={{ color: "var(--critical)" }}>
              {chains.filter((c) => c.exploitability_rating === "critical").length}
            </span>
            <span className="ac-hero-stat-label">Critical</span>
          </div>
          <div className="ac-hero-stat">
            <span className="ac-hero-stat-val" style={{ color: "var(--sev-high)" }}>
              {chains.filter((c) => c.exploitability_rating === "high").length}
            </span>
            <span className="ac-hero-stat-label">High</span>
          </div>
          <div className="ac-hero-stat">
            <span className="ac-hero-stat-val">7</span>
            <span className="ac-hero-stat-label">Templates</span>
          </div>
        </div>
      </section>

      {/* ── Template Reference (always visible) ─────────────────────── */}
      <section className="ac-section">
        <h2 className="ac-section-title">Kill Chain Templates</h2>
        <p className="ac-section-sub">
          Each template models a real-world multi-step attack. Chains are only
          synthesized when the required cross-server patterns and edges are present.
        </p>
        <div className="ac-templates-grid">
          {(["KC01", "KC02", "KC03", "KC04", "KC05", "KC06", "KC07"] as const).map((id) => {
            const matchCount = chains.filter((c) => c.kill_chain_id === id).length;
            return (
              <div key={id} className={`ac-template ${matchCount > 0 ? "ac-template-active" : ""}`}>
                <div className="ac-template-header">
                  <span className="ac-template-id">{id}</span>
                  <span className="ac-template-objective">{KC_OBJECTIVES[id]}</span>
                  {matchCount > 0 && (
                    <span className="ac-template-count">{matchCount}</span>
                  )}
                </div>
                <div className="ac-template-precedent">{KC_PRECEDENTS[id]}</div>
              </div>
            );
          })}
        </div>
      </section>

      {/* ── Chain List ─────────────────────────────────────────────── */}
      {chains.length > 0 ? (
        <section className="ac-section">
          <h2 className="ac-section-title">
            Detected Chains
            <span className="sd-section-count">{chains.length}</span>
          </h2>
          <div className="ac-chains-list">
            {chains.map((chain) => (
              <div
                key={chain.id}
                className={`ac-chain ac-chain-${chain.exploitability_rating}`}
              >
                <div className="ac-chain-header">
                  <span className={`ac-chain-rating ac-rating-${chain.exploitability_rating}`}>
                    {RATING_LABELS[chain.exploitability_rating] ?? chain.exploitability_rating}
                  </span>
                  <span className="ac-chain-score">{fmtPct(chain.exploitability_overall)}</span>
                  <span className="ac-chain-kc-id">{chain.kill_chain_id}</span>
                  <span className="ac-chain-kc-name">{chain.kill_chain_name}</span>
                  <span className="ac-chain-date">{fmtDate(chain.created_at)}</span>
                </div>

                {/* Step flow */}
                <div className="ac-chain-flow">
                  {chain.steps.map((step, i) => (
                    <React.Fragment key={step.ordinal}>
                      <div className="ac-step">
                        <span className={`ac-step-role ac-role-${step.role}`}>
                          {ROLE_LABELS[step.role] ?? step.role}
                        </span>
                        <span className="ac-step-server">{step.server_name}</span>
                      </div>
                      {i < chain.steps.length - 1 && (
                        <span className="ac-step-arrow">
                          <svg width="16" height="12" viewBox="0 0 16 12" fill="none" stroke="currentColor" strokeWidth="1.5">
                            <path d="M0 6h14M10 1l5 5-5 5" />
                          </svg>
                        </span>
                      )}
                    </React.Fragment>
                  ))}
                </div>

                {/* Narrative */}
                <div className="ac-chain-narrative">{chain.narrative}</div>

                {/* Tags */}
                <div className="ac-chain-tags">
                  {chain.owasp_refs.map((ref) => (
                    <span key={ref} className="ac-tag ac-tag-owasp">{ref}</span>
                  ))}
                  {chain.mitre_refs.map((ref) => (
                    <span key={ref} className="ac-tag ac-tag-mitre">{ref}</span>
                  ))}
                </div>

                {/* Top mitigation */}
                {chain.mitigations.length > 0 && (
                  <div className="ac-chain-mitigation">
                    <span className="ac-mit-label">Fix:</span>
                    <span className="ac-mit-action">
                      {chain.mitigations[0].action.replace(/_/g, " ")} on{" "}
                      <strong>{chain.mitigations[0].target_server_name}</strong>
                    </span>
                    <span className={`ac-mit-effect ac-mit-${chain.mitigations[0].effect === "breaks_chain" ? "breaks" : "reduces"}`}>
                      {chain.mitigations[0].effect === "breaks_chain" ? "breaks chain" : "reduces risk"}
                    </span>
                    {chain.mitigations.length > 1 && (
                      <span className="ac-mit-more">
                        +{chain.mitigations.length - 1} more
                      </span>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      ) : (
        <section className="ac-section">
          <div className="ac-empty">
            <div className="ac-empty-title">No attack chains detected</div>
            <p className="ac-empty-desc">
              Attack chain synthesis runs after the scan pipeline completes.
              Chains require cross-server risk patterns (P01&ndash;P12) and matching
              kill chain prerequisites to be detected. This is a good sign &mdash; it means
              no multi-step attack paths were found across your server configurations.
            </p>
          </div>
        </section>
      )}
    </div>
  );
}
