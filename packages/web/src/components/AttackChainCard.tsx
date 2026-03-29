"use client";
/**
 * AttackChainCard — renders attack chains involving a specific server.
 *
 * Shows each kill chain this server participates in: its role, the full
 * step flow, exploitability score, narrative, and top mitigation.
 *
 * Gracefully renders nothing if chains is null/undefined/empty — safe to
 * include unconditionally on the server detail page before the API serves
 * attack chain data.
 */

import React, { useState } from "react";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AttackChainStep {
  ordinal: number;
  server_id: string;
  server_name: string;
  role: string;
  capabilities_used?: string[];
  tools_involved?: string[];
  narrative?: string;
}

export interface AttackChainMitigation {
  action: string;
  target_server_id: string;
  target_server_name: string;
  description: string;
  breaks_steps: number[];
  effect: "breaks_chain" | "reduces_risk";
}

export interface AttackChainItem {
  id: string;
  chain_id: string;
  kill_chain_id: string;
  kill_chain_name: string;
  steps: AttackChainStep[];
  exploitability_overall: number;
  exploitability_rating: "critical" | "high" | "medium" | "low";
  narrative: string;
  mitigations: AttackChainMitigation[];
  owasp_refs: string[];
  mitre_refs: string[];
  created_at: string;
}

interface AttackChainCardProps {
  chains: AttackChainItem[] | null | undefined;
  /** The server ID of the current server detail page — highlights this server's role */
  currentServerId?: string;
}

// ── Label Maps ────────────────────────────────────────────────────────────────

const ROLE_LABELS: Record<string, string> = {
  injection_gateway: "Entry Point",
  pivot:             "Pivot",
  data_source:       "Data Source",
  executor:          "Executor",
  exfiltrator:       "Exfiltrator",
  config_writer:     "Config Writer",
  memory_writer:     "Memory Writer",
};

const RATING_LABELS: Record<string, string> = {
  critical: "Critical",
  high:     "High",
  medium:   "Medium",
  low:      "Low",
};

// ── Component ─────────────────────────────────────────────────────────────────

export default function AttackChainCard({ chains, currentServerId }: AttackChainCardProps) {
  const [expandedChain, setExpandedChain] = useState<string | null>(null);

  if (!chains || chains.length === 0) return null;

  return (
    <section className="sd-section ac-server-section">
      <h2 className="sd-section-title">
        Kill Chains Involving This Server
        <span className="sd-section-count">{chains.length}</span>
      </h2>
      <p className="sd-section-sub">
        Multi-step attack chains where this server plays a role. Each chain is backed
        by real-world CVE or published research.
      </p>

      <div className="ac-server-chains">
        {chains.map((chain) => {
          const isExpanded = expandedChain === chain.id;
          const thisServerStep = currentServerId
            ? chain.steps.find((s) => s.server_id === currentServerId)
            : null;

          return (
            <div
              key={chain.id}
              className={`ac-server-chain ac-chain-${chain.exploitability_rating}`}
            >
              {/* Header — always visible */}
              <button
                type="button"
                className="ac-server-chain-toggle"
                onClick={() => setExpandedChain(isExpanded ? null : chain.id)}
                aria-expanded={isExpanded}
              >
                <div className="ac-server-chain-hdr">
                  <span className={`ac-chain-rating ac-rating-${chain.exploitability_rating}`}>
                    {RATING_LABELS[chain.exploitability_rating]}
                  </span>
                  <span className="ac-chain-score">
                    {(chain.exploitability_overall * 100).toFixed(0)}%
                  </span>
                  <span className="ac-chain-kc-id">{chain.kill_chain_id}</span>
                  <span className="ac-chain-kc-name">{chain.kill_chain_name}</span>
                </div>

                {/* This server's role in the chain */}
                {thisServerStep && (
                  <div className="ac-server-role-badge">
                    Role: <strong>{ROLE_LABELS[thisServerStep.role] ?? thisServerStep.role}</strong>
                    {" (step "}
                    {thisServerStep.ordinal}
                    {" of "}
                    {chain.steps.length}
                    {")"}
                  </div>
                )}

                <svg
                  className={`ac-chevron ${isExpanded ? "ac-chevron-open" : ""}`}
                  width="12" height="12" viewBox="0 0 12 12"
                  fill="none" stroke="currentColor" strokeWidth="1.5"
                >
                  <path d="M3 4.5L6 7.5L9 4.5" />
                </svg>
              </button>

              {/* Expanded details */}
              {isExpanded && (
                <div className="ac-server-chain-body">
                  {/* Full step flow */}
                  <div className="ac-chain-flow">
                    {chain.steps.map((step, i) => {
                      const isCurrentServer = currentServerId && step.server_id === currentServerId;
                      return (
                        <React.Fragment key={step.ordinal}>
                          <div className={`ac-step ${isCurrentServer ? "ac-step-highlight" : ""}`}>
                            <span className={`ac-step-role ac-role-${step.role}`}>
                              {ROLE_LABELS[step.role] ?? step.role}
                            </span>
                            <span className="ac-step-server">{step.server_name}</span>
                            {step.tools_involved && step.tools_involved.length > 0 && (
                              <div className="ac-step-tools">
                                {step.tools_involved.slice(0, 3).map((t) => (
                                  <span key={t} className="ac-step-tool">{t}</span>
                                ))}
                                {step.tools_involved.length > 3 && (
                                  <span className="ac-step-tool-more">
                                    +{step.tools_involved.length - 3}
                                  </span>
                                )}
                              </div>
                            )}
                          </div>
                          {i < chain.steps.length - 1 && (
                            <span className="ac-step-arrow">
                              <svg width="16" height="12" viewBox="0 0 16 12" fill="none" stroke="currentColor" strokeWidth="1.5">
                                <path d="M0 6h14M10 1l5 5-5 5" />
                              </svg>
                            </span>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </div>

                  {/* Narrative */}
                  <div className="ac-chain-narrative">{chain.narrative}</div>

                  {/* Framework tags */}
                  <div className="ac-chain-tags">
                    {chain.owasp_refs.map((ref) => (
                      <span key={ref} className="ac-tag ac-tag-owasp">{ref}</span>
                    ))}
                    {chain.mitre_refs.map((ref) => (
                      <span key={ref} className="ac-tag ac-tag-mitre">{ref}</span>
                    ))}
                  </div>

                  {/* Mitigations */}
                  {chain.mitigations.length > 0 && (
                    <div className="ac-server-mitigations">
                      <div className="ac-mit-header">Mitigations</div>
                      {chain.mitigations.slice(0, 4).map((m, i) => (
                        <div key={i} className="ac-server-mit">
                          <span className={`ac-mit-effect ac-mit-${m.effect === "breaks_chain" ? "breaks" : "reduces"}`}>
                            {m.effect === "breaks_chain" ? "BREAKS CHAIN" : "reduces risk"}
                          </span>
                          <span className="ac-mit-desc">{m.description}</span>
                        </div>
                      ))}
                      {chain.mitigations.length > 4 && (
                        <div className="ac-mit-more">
                          +{chain.mitigations.length - 4} more mitigations
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
