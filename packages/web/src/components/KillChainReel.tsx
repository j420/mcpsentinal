"use client";
/**
 * KillChainReel — Story-lens headline + interactive Mitigation Simulator.
 *
 * Surfaces the synthesized multi-step kill chains involving this server.
 * The data comes from `packages/attack-graph` via the deep-dive endpoint's
 * `attack_chains[]` augmentation. Each chain is one card; the reel renders
 * nothing when no chains are on file (honest gap — empty state is owned
 * by the page, not this component).
 *
 * Phase 5 — Mitigation Simulator:
 *   Click any mitigation pill to "apply" it. The simulator state is
 *   per-chain (Map<chain_id, Set<mitigationIndex>>) so toggles are
 *   independent. Applied mitigations:
 *     - flip the pill into an "applied" colour
 *     - grey out the chain steps they break (via `breaks_steps[]`)
 *     - flip the chain header to ✓ BROKEN when at least one applied
 *       mitigation has effect "breaks_chain" or "breaks_step" with at
 *       least one step in `breaks_steps`
 *   A status bar above the grid summarises N-of-M chains broken plus
 *   a Reset action. Pure client state — no api round-trip required;
 *   what-if exploration without committing to anything.
 *
 * Why this lives inside KillChainReel (not its own component):
 *   - The simulator state is inherently scoped to the rendered chain
 *     set; a sibling component would have to re-derive the same Map.
 *   - The "broken steps" greying needs to land on the SAME DOM the
 *     reel renders; lifting state into a parent would mean prop-
 *     drilling broken-step Sets back into the per-chain card.
 *
 * Visual language: existing dd-* / sev-* / accent tokens only. Severity
 * is derived from `exploitability_rating` (the engine's stable rating
 * string).
 */

import React, { useCallback, useMemo, useState } from "react";
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

/** Per-chain simulator state — Set<mitigationIndex> per chain id. */
type SimulatorState = Map<string, Set<number>>;

/** Stable chain id with safe fallback when the api shape is partial. */
function chainKey(chain: DeepDiveAttackChain, idx: number): string {
  if (chain && typeof chain.chain_id === "string" && chain.chain_id.length > 0) {
    return chain.chain_id;
  }
  return `kcr-${idx}`;
}

/** Compute, per chain, the set of step ordinals broken by the currently-
 *  applied mitigations. A step is broken if AT LEAST ONE applied mitigation
 *  on this chain lists that ordinal in its `breaks_steps[]`. The function
 *  also reports whether the chain is "broken" overall — when at least one
 *  step is broken AND the breaking mitigation declares effect "breaks_chain"
 *  (or when the engine emitted no `effect` field at all — defensive). */
function deriveBroken(
  chain: DeepDiveAttackChain,
  appliedIndices: Set<number>,
): { brokenSteps: Set<number>; chainBroken: boolean } {
  const mitigations = (
    Array.isArray(chain.mitigations) ? chain.mitigations : []
  ).filter(isKillChainMitigation);
  const brokenSteps = new Set<number>();
  let chainBroken = false;
  for (const idx of appliedIndices) {
    const m = mitigations[idx];
    if (!m) continue;
    const steps = Array.isArray(m.breaks_steps) ? m.breaks_steps : [];
    for (const s of steps) {
      if (typeof s === "number" && Number.isFinite(s)) brokenSteps.add(s);
    }
    // Honest pessimism: if effect is missing, assume the engine's
    // breaks_steps[] does break the chain; if effect is "breaks_chain"
    // it does for sure; "reduces_risk" only greys steps without
    // calling the chain broken.
    const effect = typeof m.effect === "string" ? m.effect : "breaks_chain";
    if (steps.length > 0 && effect !== "reduces_risk") {
      chainBroken = true;
    }
  }
  return { brokenSteps, chainBroken };
}

export default function KillChainReel({
  chains,
  currentServerSlug,
}: KillChainReelProps) {
  // Hooks MUST be called unconditionally (rules of hooks). Initialise
  // simulator state even when there are no chains; the early-return
  // happens AFTER state is set up.
  const [applied, setApplied] = useState<SimulatorState>(() => new Map());

  const safeChains = useMemo(
    () => (Array.isArray(chains) ? chains : []),
    [chains],
  );

  // Per-chain derivations — recomputed when `applied` changes.
  const derivations = useMemo(() => {
    const out = new Map<string, ReturnType<typeof deriveBroken>>();
    for (let i = 0; i < safeChains.length; i++) {
      const chain = safeChains[i]!;
      if (!chain || typeof chain !== "object") continue;
      const key = chainKey(chain, i);
      out.set(key, deriveBroken(chain, applied.get(key) ?? new Set()));
    }
    return out;
  }, [safeChains, applied]);

  const totalChains = safeChains.length;
  const brokenCount = useMemo(() => {
    let n = 0;
    for (const d of derivations.values()) if (d.chainBroken) n++;
    return n;
  }, [derivations]);
  const appliedCount = useMemo(() => {
    let n = 0;
    for (const set of applied.values()) n += set.size;
    return n;
  }, [applied]);

  const toggleMitigation = useCallback((key: string, idx: number) => {
    setApplied((prev) => {
      const next = new Map(prev);
      const current = new Set(next.get(key) ?? new Set<number>());
      if (current.has(idx)) current.delete(idx);
      else current.add(idx);
      if (current.size === 0) next.delete(key);
      else next.set(key, current);
      return next;
    });
  }, []);

  const reset = useCallback(() => setApplied(new Map()), []);

  if (totalChains === 0) return null;

  return (
    <section className="kcr-reel" aria-labelledby="kcr-reel-title">
      <header className="kcr-reel-head">
        <h2 id="kcr-reel-title" className="kcr-reel-title">
          Attack stories involving this server
          <span className="kcr-reel-count">{totalChains}</span>
        </h2>
        <p className="kcr-reel-sub">
          Multi-step kill chains synthesized from cross-server capability
          analysis (KC01–KC07). Each chain is backed by a real-world CVE
          or published research.{" "}
          <strong className="kcr-reel-sim-hint">
            Tip: click any mitigation pill below to see how it breaks the
            chain.
          </strong>
        </p>
      </header>

      {/* Simulator status bar — shown once at least one mitigation is
          applied. Reports N-of-M chains broken + total mitigations
          applied + a Reset action. */}
      {appliedCount > 0 && (
        <div
          className="kcr-sim-bar"
          role="status"
          aria-live="polite"
          data-sim-state={
            brokenCount === totalChains
              ? "all-broken"
              : brokenCount > 0
                ? "partial"
                : "none"
          }
        >
          <span className="kcr-sim-bar-glyph" aria-hidden="true">
            🛡
          </span>
          <span className="kcr-sim-bar-text">
            <strong>
              {brokenCount} of {totalChains} chain
              {totalChains === 1 ? "" : "s"} broken
            </strong>
            {" · "}
            {appliedCount} mitigation{appliedCount === 1 ? "" : "s"} applied
          </span>
          <button
            type="button"
            className="kcr-sim-bar-reset"
            onClick={reset}
            aria-label="Reset all applied mitigations"
          >
            Reset
          </button>
        </div>
      )}

      <div className="kcr-reel-grid">
        {safeChains.map((chain, idx) => {
          if (!chain || typeof chain !== "object") return null;
          const key = chainKey(chain, idx);
          const sev = RATING_TO_SEV[chain.exploitability_rating] ?? "medium";
          const steps = (Array.isArray(chain.steps) ? chain.steps : []).filter(
            isKillChainStep,
          );
          const mitigations = (
            Array.isArray(chain.mitigations) ? chain.mitigations : []
          ).filter(isKillChainMitigation);
          const owaspRefs = Array.isArray(chain.owasp_refs)
            ? chain.owasp_refs
            : [];
          const mitreRefs = Array.isArray(chain.mitre_refs)
            ? chain.mitre_refs
            : [];
          const refs = [...owaspRefs, ...mitreRefs].filter(
            (s): s is string => typeof s === "string" && s.length > 0,
          );
          const score =
            typeof chain.exploitability_overall === "number"
              ? (chain.exploitability_overall * 100).toFixed(0)
              : null;
          const appliedSet = applied.get(key) ?? new Set<number>();
          const { brokenSteps, chainBroken } =
            derivations.get(key) ?? { brokenSteps: new Set(), chainBroken: false };

          return (
            <article
              key={key}
              className="kcr-card"
              data-sev={sev}
              data-chain-broken={chainBroken ? "true" : undefined}
              style={{ borderLeftColor: `var(--sev-${sev})` }}
            >
              <header className="kcr-card-head">
                <div className="kcr-card-title-row">
                  {chain.kill_chain_id && (
                    <span className="kcr-card-kc">{chain.kill_chain_id}</span>
                  )}
                  {chain.kill_chain_name && (
                    <span className="kcr-card-kc-name">
                      {chain.kill_chain_name}
                    </span>
                  )}
                  {chain.exploitability_rating && (
                    <span
                      className={`sev-badge sev-${sev}`}
                      aria-label={`Exploitability: ${chain.exploitability_rating}`}
                    >
                      {chain.exploitability_rating}
                    </span>
                  )}
                  {score !== null && (
                    <span
                      className="kcr-card-score"
                      aria-label="Exploitability score"
                    >
                      {score}/100
                    </span>
                  )}
                  {chainBroken && (
                    <span
                      className="kcr-card-broken"
                      aria-label="Chain broken by applied mitigations"
                    >
                      ✓ BROKEN
                    </span>
                  )}
                </div>
                {refs.length > 0 && (
                  <div className="kcr-card-refs">{refs.join(" · ")}</div>
                )}
              </header>

              {steps.length > 0 && (
                <ol className="kcr-steps" aria-label="Attack steps">
                  {steps.map((step, sIdx) => {
                    const isCurrent =
                      currentServerSlug &&
                      step.server_id === currentServerSlug;
                    const role = step.role
                      ? ROLE_LABEL[step.role] ?? step.role
                      : "";
                    const tools = step.tools_involved ?? [];
                    const isBroken =
                      typeof step.ordinal === "number" &&
                      brokenSteps.has(step.ordinal);
                    return (
                      <li
                        key={`${step.ordinal}-${sIdx}`}
                        className="kcr-step"
                        data-current={isCurrent ? "true" : undefined}
                        data-broken={isBroken ? "true" : undefined}
                        aria-label={
                          isBroken
                            ? `Step ${step.ordinal} broken by an applied mitigation`
                            : undefined
                        }
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
                <div className="kcr-mit-sim">
                  <div className="kcr-mit-sim-label">
                    {mitigations.length} mitigation
                    {mitigations.length === 1 ? "" : "s"} that break this chain
                    — click to apply
                  </div>
                  <ul className="kcr-mit-sim-list" role="group">
                    {mitigations.slice(0, 5).map((m, i) => {
                      const isApplied = appliedSet.has(i);
                      const stepsLabel =
                        Array.isArray(m.breaks_steps) && m.breaks_steps.length > 0
                          ? `breaks step${
                              m.breaks_steps.length === 1 ? "" : "s"
                            } ${m.breaks_steps.join(", ")}`
                          : null;
                      const desc = m.description ?? m.action ?? "—";
                      const target =
                        typeof m.target_server_name === "string" &&
                        m.target_server_name.length > 0
                          ? m.target_server_name
                          : null;
                      return (
                        <li key={i} className="kcr-mit-sim-item">
                          <button
                            type="button"
                            className={`kcr-mit-sim-pill${
                              isApplied ? " kcr-mit-sim-pill-applied" : ""
                            }`}
                            data-applied={isApplied ? "true" : undefined}
                            aria-pressed={isApplied}
                            onClick={() => toggleMitigation(key, i)}
                            title={
                              stepsLabel
                                ? `${desc} (${stepsLabel})`
                                : desc
                            }
                          >
                            <span
                              className="kcr-mit-sim-pill-glyph"
                              aria-hidden="true"
                            >
                              {isApplied ? "✓" : "+"}
                            </span>
                            {target && (
                              <span className="kcr-mit-sim-pill-target">
                                {target}
                              </span>
                            )}
                            <span className="kcr-mit-sim-pill-desc">{desc}</span>
                            {stepsLabel && (
                              <span className="kcr-mit-sim-pill-steps">
                                {stepsLabel}
                              </span>
                            )}
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                  {chainBroken && (
                    <p className="kcr-mit-sim-status">
                      ✓ This chain is broken — the attacker cannot reach{" "}
                      {brokenSteps.size > 1
                        ? `steps ${Array.from(brokenSteps)
                            .sort((a, b) => a - b)
                            .join(", ")}`
                        : `step ${Array.from(brokenSteps)[0]}`}
                      .
                    </p>
                  )}
                </div>
              )}
            </article>
          );
        })}
      </div>
    </section>
  );
}
