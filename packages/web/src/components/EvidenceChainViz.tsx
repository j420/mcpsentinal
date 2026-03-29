"use client";
/**
 * EvidenceChainViz — Renders structured evidence chains from attack-graph
 * analysis. Shows source → propagation → sink → impact links as a visual flow.
 *
 * Props:
 *   chain — A single evidence chain object (from AttackChain.evidence or
 *           individual finding evidence). May have partial data.
 *   compact — If true, renders a condensed version (no impact details).
 */

import React from "react";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface EvidenceLink {
  type: "source" | "propagation" | "sink" | "mitigation" | "impact";
  location?: string | null;
  observed?: string | null;
  rationale?: string | null;
  source_type?: string | null;
  propagation_type?: string | null;
  sink_type?: string | null;
  mitigation_type?: string | null;
  impact_type?: string | null;
  present?: boolean;
  scope?: string | null;
}

export interface EvidenceChain {
  links?: EvidenceLink[] | null;
  confidence?: number | null;
  confidence_factors?: Array<{ factor: string; value: number; description: string }> | null;
}

export interface EvidenceChainVizProps {
  chain: EvidenceChain;
  compact?: boolean;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const TYPE_COLORS: Record<string, string> = {
  source: "#dc2626",
  propagation: "#f59e0b",
  sink: "#7c3aed",
  mitigation: "#059669",
  impact: "#1d4ed8",
};

const TYPE_LABELS: Record<string, string> = {
  source: "Source",
  propagation: "Propagation",
  sink: "Sink",
  mitigation: "Mitigation",
  impact: "Impact",
};

function truncate(s: string | null | undefined, max: number): string {
  if (!s) return "";
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + "…";
}

function linkSubtype(link: EvidenceLink): string | null {
  return (
    link.source_type ??
    link.propagation_type ??
    link.sink_type ??
    link.mitigation_type ??
    link.impact_type ??
    null
  );
}

function formatSubtype(raw: string): string {
  return raw.replace(/[-_]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// ── Components ────────────────────────────────────────────────────────────────

function LinkBadge({ link }: { link: EvidenceLink }) {
  const color = TYPE_COLORS[link.type] ?? "#6b7280";
  const label = TYPE_LABELS[link.type] ?? link.type;
  const sub = linkSubtype(link);

  return (
    <div
      className="evidence-link-badge"
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        padding: "4px 10px",
        borderRadius: "6px",
        border: `1px solid ${color}`,
        background: `${color}10`,
        fontSize: "13px",
      }}
    >
      <span
        style={{
          width: "8px",
          height: "8px",
          borderRadius: "50%",
          background: color,
          flexShrink: 0,
        }}
      />
      <span style={{ fontWeight: 600, color }}>{label}</span>
      {sub && (
        <span style={{ color: "#6b7280", fontSize: "12px" }}>
          {formatSubtype(sub)}
        </span>
      )}
    </div>
  );
}

function LinkCard({
  link,
  compact,
}: {
  link: EvidenceLink;
  compact: boolean;
}) {
  const color = TYPE_COLORS[link.type] ?? "#6b7280";

  return (
    <div
      className="evidence-link-card"
      style={{
        borderLeft: `3px solid ${color}`,
        padding: "8px 12px",
        margin: "4px 0",
        background: "#fafafa",
        borderRadius: "0 6px 6px 0",
      }}
    >
      <LinkBadge link={link} />

      {link.location && (
        <div style={{ marginTop: "4px", fontSize: "12px", color: "#4b5563" }}>
          <strong>Location:</strong> {truncate(link.location, 120)}
        </div>
      )}

      {link.observed && (
        <div style={{ marginTop: "2px", fontSize: "12px", color: "#4b5563" }}>
          <strong>Observed:</strong> {truncate(link.observed, 200)}
        </div>
      )}

      {!compact && link.rationale && (
        <div style={{ marginTop: "2px", fontSize: "12px", color: "#6b7280" }}>
          <em>{truncate(link.rationale, 300)}</em>
        </div>
      )}

      {link.type === "mitigation" && (
        <div
          style={{
            marginTop: "2px",
            fontSize: "12px",
            color: link.present ? "#059669" : "#dc2626",
            fontWeight: 600,
          }}
        >
          {link.present ? "✓ Present" : "✗ Missing"}
        </div>
      )}

      {!compact && link.type === "impact" && link.scope && (
        <div style={{ marginTop: "2px", fontSize: "12px", color: "#1d4ed8" }}>
          <strong>Scope:</strong> {link.scope}
        </div>
      )}
    </div>
  );
}

function FlowArrow() {
  return (
    <div
      className="evidence-flow-arrow"
      style={{
        display: "flex",
        justifyContent: "center",
        padding: "2px 0",
        color: "#9ca3af",
        fontSize: "14px",
      }}
    >
      ↓
    </div>
  );
}

function ConfidenceBar({ confidence }: { confidence: number }) {
  const clamped = Math.min(1, Math.max(0, confidence));
  const pct = Math.round(clamped * 100);
  let barColor = "#059669";
  if (clamped < 0.5) barColor = "#dc2626";
  else if (clamped < 0.75) barColor = "#f59e0b";

  return (
    <div className="evidence-confidence-bar" style={{ marginTop: "8px" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          fontSize: "12px",
          color: "#6b7280",
          marginBottom: "2px",
        }}
      >
        <span>Confidence</span>
        <span>{pct}%</span>
      </div>
      <div
        style={{
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
            background: barColor,
            borderRadius: "3px",
            transition: "width 0.3s ease",
          }}
        />
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function EvidenceChainViz({ chain, compact = false }: EvidenceChainVizProps) {
  const links = chain.links ?? [];
  const confidence = chain.confidence ?? null;
  const confidenceFactors = chain.confidence_factors ?? [];

  if (links.length === 0) {
    return (
      <div className="evidence-chain-empty" style={{ color: "#9ca3af", fontSize: "13px" }}>
        No evidence chain available.
      </div>
    );
  }

  // Separate flow links (source/propagation/sink) from metadata links
  const flowLinks = links.filter(
    (l) => l.type === "source" || l.type === "propagation" || l.type === "sink"
  );
  const mitigationLinks = links.filter((l) => l.type === "mitigation");
  const impactLinks = links.filter((l) => l.type === "impact");

  return (
    <div className="evidence-chain-viz" style={{ fontFamily: "system-ui, sans-serif" }}>
      {/* Flow section */}
      {flowLinks.length > 0 && (
        <div className="evidence-flow">
          <div
            style={{
              fontSize: "11px",
              fontWeight: 600,
              color: "#9ca3af",
              textTransform: "uppercase" as const,
              letterSpacing: "0.05em",
              marginBottom: "4px",
            }}
          >
            Data Flow
          </div>
          {flowLinks.map((link, idx) => (
            <React.Fragment key={`flow-${idx}`}>
              <LinkCard link={link} compact={compact} />
              {idx < flowLinks.length - 1 && <FlowArrow />}
            </React.Fragment>
          ))}
        </div>
      )}

      {/* Mitigations */}
      {mitigationLinks.length > 0 && (
        <div className="evidence-mitigations" style={{ marginTop: "12px" }}>
          <div
            style={{
              fontSize: "11px",
              fontWeight: 600,
              color: "#9ca3af",
              textTransform: "uppercase" as const,
              letterSpacing: "0.05em",
              marginBottom: "4px",
            }}
          >
            Mitigations
          </div>
          {mitigationLinks.map((link, idx) => (
            <LinkCard key={`mit-${idx}`} link={link} compact={compact} />
          ))}
        </div>
      )}

      {/* Impact (hidden in compact mode) */}
      {!compact && impactLinks.length > 0 && (
        <div className="evidence-impact" style={{ marginTop: "12px" }}>
          <div
            style={{
              fontSize: "11px",
              fontWeight: 600,
              color: "#9ca3af",
              textTransform: "uppercase" as const,
              letterSpacing: "0.05em",
              marginBottom: "4px",
            }}
          >
            Impact
          </div>
          {impactLinks.map((link, idx) => (
            <LinkCard key={`impact-${idx}`} link={link} compact={compact} />
          ))}
        </div>
      )}

      {/* Confidence bar */}
      {confidence !== null && <ConfidenceBar confidence={confidence} />}

      {/* Confidence factors */}
      {!compact && confidenceFactors.length > 0 && (
        <div className="evidence-factors" style={{ marginTop: "8px" }}>
          <div
            style={{
              fontSize: "11px",
              fontWeight: 600,
              color: "#9ca3af",
              textTransform: "uppercase" as const,
              letterSpacing: "0.05em",
              marginBottom: "4px",
            }}
          >
            Confidence Factors
          </div>
          {confidenceFactors.map((f, idx) => (
            <div
              key={`factor-${idx}`}
              style={{
                display: "flex",
                justifyContent: "space-between",
                fontSize: "12px",
                color: "#4b5563",
                padding: "2px 0",
              }}
            >
              <span>{f.description || f.factor}</span>
              <span style={{ fontWeight: 600 }}>{(f.value * 100).toFixed(0)}%</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default EvidenceChainViz;
