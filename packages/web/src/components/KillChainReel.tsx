/**
 * KillChainReel — Story-lens headline for the Deep Dive page.
 *
 * Surfaces the synthesized multi-step kill chains involving this server.
 * The data comes from `packages/attack-graph` via the deep-dive endpoint's
 * `attack_chains[]` augmentation. Each chain is one card; the reel renders
 * nothing when no chains are on file (honest gap — empty state is owned
 * by the page, not this component).
 *
 * Why a separate component (not the legacy AttackChainCard):
 *   - Consumes `DeepDiveAttackChain` directly from `lib/deep-dive.ts` —
 *     no shape adaptation, no field drift.
 *   - Internal correlation ids (`id`, `config_id`, `created_at`) are NOT
 *     in the wire shape, so this component never reaches for them.
 *   - Server component — no client JS. Native `<details>` toggles per-card.
 *
 * Visual language: existing dd-* / sev-* tokens only. Severity is derived
 * from `exploitability_rating` (the engine's stable rating string).
 */

import React from "react";
import type { DeepDiveAttackChain } from "@/lib/deep-dive";

interface KillChainStep {
  ordinal: number;
  server_id?: string;
  server_name?: string;
  role?: string;
  capabilities_used?: string[];
  tools_involved?: string[];
  narrative?: string;
}

interface KillChainMitigation {
  action?: string;
  target_server_name?: string | null;
  description?: string;
  breaks_steps?: number[];
  effect?: string;
}

interface KillChainReelProps {
  chains: DeepDiveAttackChain[] | undefined;
  /** Highlights the step where the current server appears. */
  currentServerSlug?: string;
}

const ROLE_LABEL: Record<string, string> = {
  injection_gateway: "Entry point",
  pivot: "Pivot",
  data_source: "Data source",
  executor: "Executor",
  exfiltrator: "Exfiltrator",
  config_writer: "Config writer",
  memory_writer: "Memory writer",
};

const RATING_TO_SEV: Record<string, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

function isKillChainStep(value: unknown): value is KillChainStep {
  return typeof value === "object" && value !== null && "ordinal" in value;
}
function isKillChainMitigation(value: unknown): value is KillChainMitigation {
  return typeof value === "object" && value !== null;
}

export default function KillChainReel({
  chains,
  currentServerSlug,
}: KillChainReelProps) {
  if (!chains || chains.length === 0) return null;

  return (
    <section className="kcr-reel" aria-labelledby="kcr-reel-title">
      <header className="kcr-reel-head">
        <h2 id="kcr-reel-title" className="kcr-reel-title">
          Attack stories involving this server
          <span className="kcr-reel-count">{chains.length}</span>
        </h2>
        <p className="kcr-reel-sub">
          Multi-step kill chains synthesized from cross-server capability
          analysis (KC01–KC07). Each chain is backed by a real-world CVE
          or published research.
        </p>
      </header>

      <div className="kcr-reel-grid">
        {chains.map((chain) => {
          const sev = RATING_TO_SEV[chain.exploitability_rating] ?? "medium";
          const steps = (chain.steps ?? []).filter(isKillChainStep);
          const mitigations = (chain.mitigations ?? []).filter(
            isKillChainMitigation,
          );
          const refs = [...chain.owasp_refs, ...chain.mitre_refs].filter(
            (s) => s.length > 0,
          );

          return (
            <article
              key={chain.chain_id}
              className="kcr-card"
              data-sev={sev}
              style={{ borderLeftColor: `var(--sev-${sev})` }}
            >
              <header className="kcr-card-head">
                <div className="kcr-card-title-row">
                  <span className="kcr-card-kc">{chain.kill_chain_id}</span>
                  <span className="kcr-card-kc-name">
                    {chain.kill_chain_name}
                  </span>
                  <span
                    className={`sev-badge sev-${sev}`}
                    aria-label={`Exploitability: ${chain.exploitability_rating}`}
                  >
                    {chain.exploitability_rating}
                  </span>
                  <span className="kcr-card-score" aria-label="Exploitability score">
                    {(chain.exploitability_overall * 100).toFixed(0)}/100
                  </span>
                </div>
                {refs.length > 0 && (
                  <div className="kcr-card-refs">{refs.join(" · ")}</div>
                )}
              </header>

              {steps.length > 0 && (
                <ol className="kcr-steps" aria-label="Attack steps">
                  {steps.map((step, idx) => {
                    const isCurrent =
                      currentServerSlug &&
                      step.server_id === currentServerSlug;
                    const role = step.role
                      ? ROLE_LABEL[step.role] ?? step.role
                      : "";
                    const tools = step.tools_involved ?? [];
                    return (
                      <li
                        key={`${step.ordinal}-${idx}`}
                        className="kcr-step"
                        data-current={isCurrent ? "true" : undefined}
                      >
                        <span className="kcr-step-ord" aria-hidden="true">
                          {step.ordinal}
                        </span>
                        <div className="kcr-step-body">
                          {step.server_name && (
                            <div className="kcr-step-server">
                              {step.server_name}
                            </div>
                          )}
                          {role && (
                            <div className="kcr-step-role">{role}</div>
                          )}
                          {tools.length > 0 && (
                            <div className="kcr-step-tools">
                              {tools.slice(0, 3).join(", ")}
                              {tools.length > 3 ? ` +${tools.length - 3}` : ""}
                            </div>
                          )}
                        </div>
                      </li>
                    );
                  })}
                </ol>
              )}

              {chain.narrative && (
                <p className="kcr-narrative">{chain.narrative}</p>
              )}

              {mitigations.length > 0 && (
                <details className="kcr-mit">
                  <summary className="kcr-mit-summary">
                    {mitigations.length} mitigation
                    {mitigations.length === 1 ? "" : "s"} that break this chain
                  </summary>
                  <ul className="kcr-mit-list">
                    {mitigations.slice(0, 5).map((m, i) => (
                      <li key={i} className="kcr-mit-item">
                        {m.target_server_name && (
                          <span className="kcr-mit-target">
                            {m.target_server_name}
                          </span>
                        )}
                        <span className="kcr-mit-desc">
                          {m.description ?? m.action ?? "—"}
                        </span>
                        {m.breaks_steps && m.breaks_steps.length > 0 && (
                          <span className="kcr-mit-steps">
                            breaks step
                            {m.breaks_steps.length === 1 ? "" : "s"}{" "}
                            {m.breaks_steps.join(", ")}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                </details>
              )}
            </article>
          );
        })}
      </div>
    </section>
  );
}
