/**
 * Attack Chains — Listing page showing all detected multi-step attack chains
 * across the MCP ecosystem.
 *
 * Fetches chains from the API, grouped by aggregate risk level, with links
 * to individual server detail pages.
 */

import React from "react";
import Link from "next/link";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:3100";

// ── Types ─────────────────────────────────────────────────────────────────────

interface ChainStep {
  ordinal: number;
  server_id: string;
  server_name: string;
  role: string;
}

interface AttackChainSummary {
  chain_id: string;
  config_id: string;
  kill_chain_id: string;
  kill_chain_name: string;
  steps: ChainStep[];
  exploitability_overall: number;
  exploitability_rating: string;
  narrative: string;
  owasp_refs: string[];
  mitre_refs: string[];
  created_at: string;
}

// ── Data fetching ─────────────────────────────────────────────────────────────

async function getAttackChains(): Promise<AttackChainSummary[]> {
  try {
    const res = await fetch(`${API_BASE}/api/v1/attack-chains`, {
      next: { revalidate: 3600 },
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.chains ?? [];
  } catch {
    return [];
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const RATING_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: "#fef2f2", text: "#dc2626", border: "#fecaca" },
  high: { bg: "#fffbeb", text: "#d97706", border: "#fde68a" },
  medium: { bg: "#eff6ff", text: "#2563eb", border: "#bfdbfe" },
  low: { bg: "#f0fdf4", text: "#16a34a", border: "#bbf7d0" },
};

function RatingBadge({ rating }: { rating: string }) {
  const colors = RATING_COLORS[rating] ?? { bg: "#f3f4f6", text: "#6b7280", border: "#d1d5db" };
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 10px",
        borderRadius: "9999px",
        background: colors.bg,
        color: colors.text,
        border: `1px solid ${colors.border}`,
        fontWeight: 700,
        fontSize: "12px",
        textTransform: "uppercase" as const,
      }}
    >
      {rating}
    </span>
  );
}

function ExploitabilityBar({ value }: { value: number }) {
  const clamped = Math.min(1, Math.max(0, value));
  const pct = Math.round(clamped * 100);
  let color = "#16a34a";
  if (clamped >= 0.75) color = "#dc2626";
  else if (clamped >= 0.55) color = "#d97706";
  else if (clamped >= 0.35) color = "#2563eb";

  return (
    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
      <div
        style={{
          flex: 1,
          height: "6px",
          background: "#e5e7eb",
          borderRadius: "3px",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            width: `${pct}%`,
            height: "100%",
            background: color,
            borderRadius: "3px",
          }}
        />
      </div>
      <span style={{ fontSize: "12px", fontWeight: 600, color, minWidth: "36px" }}>
        {pct}%
      </span>
    </div>
  );
}

function StepFlow({ steps }: { steps: ChainStep[] }) {
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: "4px", alignItems: "center" }}>
      {steps.map((step, idx) => (
        <React.Fragment key={step.ordinal}>
          <span
            style={{
              fontSize: "13px",
              padding: "2px 6px",
              borderRadius: "4px",
              background: "#f3f4f6",
              border: "1px solid #e5e7eb",
            }}
          >
            {step.server_name}
          </span>
          {idx < steps.length - 1 && (
            <span style={{ color: "#9ca3af", fontSize: "13px" }}>→</span>
          )}
        </React.Fragment>
      ))}
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default async function AttackChainsPage() {
  const chains = await getAttackChains();

  const critical = chains.filter((c) => c.exploitability_rating === "critical");
  const high = chains.filter((c) => c.exploitability_rating === "high");
  const medium = chains.filter((c) => c.exploitability_rating === "medium");
  const low = chains.filter((c) => c.exploitability_rating === "low");

  return (
    <main style={{ maxWidth: "960px", margin: "0 auto", padding: "32px 16px", fontFamily: "system-ui, sans-serif" }}>
      <h1 style={{ fontSize: "28px", fontWeight: 800, marginBottom: "8px" }}>
        Attack Chains
      </h1>
      <p style={{ color: "#6b7280", fontSize: "15px", marginBottom: "24px" }}>
        Multi-step kill chains detected across MCP server configurations.
        Each chain maps to a documented real-world attack with CVE or research precedent.
      </p>

      {/* Stats bar */}
      <div
        style={{
          display: "flex",
          gap: "24px",
          padding: "12px 16px",
          background: "#f9fafb",
          borderRadius: "8px",
          border: "1px solid #e5e7eb",
          marginBottom: "24px",
          flexWrap: "wrap",
        }}
      >
        <div>
          <span style={{ fontWeight: 700, fontSize: "20px" }}>{chains.length}</span>
          <span style={{ color: "#6b7280", marginLeft: "6px", fontSize: "14px" }}>Total Chains</span>
        </div>
        {critical.length > 0 && (
          <div>
            <span style={{ fontWeight: 700, fontSize: "20px", color: "#dc2626" }}>{critical.length}</span>
            <span style={{ color: "#6b7280", marginLeft: "6px", fontSize: "14px" }}>Critical</span>
          </div>
        )}
        {high.length > 0 && (
          <div>
            <span style={{ fontWeight: 700, fontSize: "20px", color: "#d97706" }}>{high.length}</span>
            <span style={{ color: "#6b7280", marginLeft: "6px", fontSize: "14px" }}>High</span>
          </div>
        )}
      </div>

      {/* Chain list */}
      {chains.length === 0 ? (
        <div
          style={{
            textAlign: "center",
            padding: "48px",
            color: "#9ca3af",
            border: "1px dashed #d1d5db",
            borderRadius: "8px",
          }}
        >
          No attack chains detected yet. Run the scan pipeline to generate analysis.
        </div>
      ) : (
        <div>
          {[
            { label: "Critical", items: critical },
            { label: "High", items: high },
            { label: "Medium", items: medium },
            { label: "Low", items: low },
          ]
            .filter((group) => group.items.length > 0)
            .map((group) => (
              <div key={group.label} style={{ marginBottom: "24px" }}>
                <h2 style={{ fontSize: "18px", fontWeight: 700, marginBottom: "12px" }}>
                  {group.label} ({group.items.length})
                </h2>
                {group.items.map((chain) => (
                  <div
                    key={chain.chain_id}
                    style={{
                      border: "1px solid #e5e7eb",
                      borderRadius: "8px",
                      padding: "16px",
                      marginBottom: "12px",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                        marginBottom: "8px",
                      }}
                    >
                      <div>
                        <div style={{ fontWeight: 700 }}>{chain.kill_chain_name}</div>
                        <div style={{ fontSize: "12px", color: "#6b7280" }}>
                          {chain.kill_chain_id} &middot; {chain.chain_id.slice(0, 8)}
                        </div>
                      </div>
                      <RatingBadge rating={chain.exploitability_rating} />
                    </div>

                    <p style={{ fontSize: "14px", color: "#374151", lineHeight: 1.5, margin: "0 0 8px" }}>
                      {chain.narrative}
                    </p>

                    <div style={{ marginBottom: "8px" }}>
                      <StepFlow steps={chain.steps} />
                    </div>

                    <ExploitabilityBar value={chain.exploitability_overall} />

                    {(chain.owasp_refs.length > 0 || chain.mitre_refs.length > 0) && (
                      <div style={{ marginTop: "8px", display: "flex", gap: "16px", fontSize: "12px", color: "#6b7280" }}>
                        {chain.owasp_refs.length > 0 && (
                          <span><strong>OWASP:</strong> {chain.owasp_refs.join(", ")}</span>
                        )}
                        {chain.mitre_refs.length > 0 && (
                          <span><strong>MITRE:</strong> {chain.mitre_refs.join(", ")}</span>
                        )}
                      </div>
                    )}

                    {/* Server links */}
                    <div style={{ marginTop: "8px", display: "flex", gap: "8px", flexWrap: "wrap" }}>
                      {chain.steps.map((step) => (
                        <Link
                          key={step.server_id}
                          href={`/servers/${step.server_name.toLowerCase().replace(/\s+/g, "-")}`}
                          style={{
                            fontSize: "12px",
                            color: "#3b82f6",
                            textDecoration: "none",
                          }}
                        >
                          {step.server_name} →
                        </Link>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ))}
        </div>
      )}
    </main>
  );
}
