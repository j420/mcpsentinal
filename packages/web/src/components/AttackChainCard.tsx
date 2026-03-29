"use client";
/**
 * AttackChainCard — Renders a single attack chain on server detail pages.
 *
 * Shows the kill chain name, exploitability score, step flow, mitigations,
 * and framework references. Used on /servers/[slug] to surface cross-server
 * risks involving that server.
 */

import React from "react";
import { EvidenceChainViz, type EvidenceChain } from "./EvidenceChainViz";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AttackStep {
  ordinal: number;
  server_id: string;
  server_name: string;
  role: string;
  capabilities_used: string[];
  tools_involved: string[];
  narrative: string;
}

export interface Mitigation {
  action: string;
  target_server_name: string;
  description: string;
  breaks_steps: number[];
  effect: "breaks_chain" | "reduces_risk";
}

export interface AttackChainData {
  chain_id: string;
  kill_chain_id: string;
  kill_chain_name: string;
  steps: AttackStep[];
  exploitability_overall: number;
  exploitability_rating: string;
  narrative: string;
  mitigations: Mitigation[];
  owasp_refs: string[];
  mitre_refs: string[];
  evidence?: EvidenceChain;
}

export interface AttackChainCardProps {
  chain: AttackChainData;
  /** The server being viewed — used to highlight the current server in steps */
  currentServerId?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const RATING_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#f59e0b",
  medium: "#3b82f6",
  low: "#059669",
};

function ratingBadge(rating: string) {
  const color = RATING_COLORS[rating] ?? "#6b7280";
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 8px",
        borderRadius: "4px",
        background: `${color}15`,
        color,
        fontWeight: 700,
        fontSize: "12px",
        textTransform: "uppercase" as const,
      }}
    >
      {rating}
    </span>
  );
}

function exploitabilityPct(overall: number): string {
  const clamped = Math.min(1, Math.max(0, overall));
  return `${Math.round(clamped * 100)}%`;
}

// ── Component ─────────────────────────────────────────────────────────────────

export function AttackChainCard({ chain, currentServerId }: AttackChainCardProps) {
  const steps = chain.steps ?? [];
  const mitigations = chain.mitigations ?? [];

  return (
    <div
      className="attack-chain-card"
      style={{
        border: "1px solid #e5e7eb",
        borderRadius: "8px",
        padding: "16px",
        marginBottom: "16px",
        fontFamily: "system-ui, sans-serif",
      }}
    >
      {/* Header */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "12px",
        }}
      >
        <div>
          <div style={{ fontWeight: 700, fontSize: "16px" }}>
            {chain.kill_chain_name}
          </div>
          <div style={{ fontSize: "12px", color: "#6b7280" }}>
            {chain.kill_chain_id} &middot; {chain.chain_id.slice(0, 8)}
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          {ratingBadge(chain.exploitability_rating)}
          <div style={{ fontSize: "12px", color: "#6b7280", marginTop: "2px" }}>
            Exploitability: {exploitabilityPct(chain.exploitability_overall)}
          </div>
        </div>
      </div>

      {/* Narrative */}
      <p style={{ fontSize: "14px", color: "#374151", lineHeight: 1.5, margin: "0 0 12px" }}>
        {chain.narrative}
      </p>

      {/* Steps */}
      {steps.length > 0 && (
        <div style={{ marginBottom: "12px" }}>
          <div style={{ fontSize: "11px", fontWeight: 600, color: "#9ca3af", textTransform: "uppercase" as const, letterSpacing: "0.05em", marginBottom: "6px" }}>
            Attack Steps
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "4px", alignItems: "center" }}>
            {steps.map((step, idx) => {
              const isCurrent = step.server_id === currentServerId;
              return (
                <React.Fragment key={step.ordinal}>
                  <div
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "4px",
                      padding: "4px 8px",
                      borderRadius: "4px",
                      border: isCurrent ? "2px solid #3b82f6" : "1px solid #d1d5db",
                      background: isCurrent ? "#eff6ff" : "#f9fafb",
                      fontSize: "13px",
                    }}
                  >
                    <span style={{ fontWeight: 600, color: "#6b7280", fontSize: "11px" }}>
                      {step.ordinal}.
                    </span>
                    <span style={{ fontWeight: isCurrent ? 700 : 400 }}>
                      {step.server_name}
                    </span>
                    <span style={{ fontSize: "11px", color: "#9ca3af" }}>
                      ({step.role.replace(/_/g, " ")})
                    </span>
                  </div>
                  {idx < steps.length - 1 && (
                    <span style={{ color: "#9ca3af", fontSize: "14px" }}>→</span>
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </div>
      )}

      {/* Mitigations */}
      {mitigations.length > 0 && (
        <div style={{ marginBottom: "12px" }}>
          <div style={{ fontSize: "11px", fontWeight: 600, color: "#9ca3af", textTransform: "uppercase" as const, letterSpacing: "0.05em", marginBottom: "6px" }}>
            Mitigations
          </div>
          {mitigations.map((m, idx) => (
            <div
              key={idx}
              style={{
                display: "flex",
                gap: "8px",
                alignItems: "baseline",
                fontSize: "13px",
                padding: "4px 0",
                borderBottom: idx < mitigations.length - 1 ? "1px solid #f3f4f6" : "none",
              }}
            >
              <span
                style={{
                  flexShrink: 0,
                  fontWeight: 600,
                  fontSize: "11px",
                  color: m.effect === "breaks_chain" ? "#059669" : "#f59e0b",
                }}
              >
                {m.effect === "breaks_chain" ? "BREAKS" : "REDUCES"}
              </span>
              <span style={{ color: "#374151" }}>
                <strong>{m.target_server_name}:</strong> {m.description}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Framework refs */}
      {(chain.owasp_refs.length > 0 || chain.mitre_refs.length > 0) && (
        <div style={{ display: "flex", gap: "16px", flexWrap: "wrap", fontSize: "12px", color: "#6b7280" }}>
          {chain.owasp_refs.length > 0 && (
            <span>
              <strong>OWASP:</strong> {chain.owasp_refs.join(", ")}
            </span>
          )}
          {chain.mitre_refs.length > 0 && (
            <span>
              <strong>MITRE:</strong> {chain.mitre_refs.join(", ")}
            </span>
          )}
        </div>
      )}

      {/* Evidence */}
      {chain.evidence && (
        <div style={{ marginTop: "12px" }}>
          <EvidenceChainViz chain={chain.evidence} compact />
        </div>
      )}
    </div>
  );
}

export default AttackChainCard;
