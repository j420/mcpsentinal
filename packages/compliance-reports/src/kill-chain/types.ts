/**
 * Kill-chain narrative synthesizer — input types.
 *
 * The output type `KillChainNarrative` lives in `../types.ts` (Agent 1's
 * contract) and is re-exported here so callers only need to import one
 * module.
 *
 * Design principle (Phase 5 chunk 5.3): the synthesizer takes typed inputs
 * only — no DB access, no file I/O — which makes unit tests deterministic.
 * Production code (`packages/attack-graph` CLI + API endpoints) wires the
 * real `attack_chains` rows and the Phase 4 CVE corpus into these shapes.
 */
import type { KillChainNarrative } from "../types.js";

export type { KillChainNarrative };

/**
 * Stable KC identifiers. These MUST match the seven kill-chain templates
 * exported from `packages/attack-graph/src/kill-chains.ts` (KC01..KC07).
 * The `integration.test.ts` test asserts coverage is exactly this set so
 * any future template addition/removal surfaces here as a failing test.
 */
export type KCId = "KC01" | "KC02" | "KC03" | "KC04" | "KC05" | "KC06" | "KC07";

export const ALL_KC_IDS: readonly KCId[] = [
  "KC01",
  "KC02",
  "KC03",
  "KC04",
  "KC05",
  "KC06",
  "KC07",
];

/**
 * Narrowed, synthesizer-facing shape of a persisted `attack_chains` row.
 *
 * The production `attack_chains` table (see `@mcp-sentinel/database`'s
 * `AttackChainSchema`) stores more columns than the synthesizer consumes;
 * this interface projects only the fields we read so tests can pass
 * synthetic objects without needing the full DB row shape.
 *
 * Notes:
 *   - `edge_path` is the ordered human-readable step sequence (e.g.
 *     ["web-scraping", "accesses-filesystem", "sends-network"]). Production
 *     code builds this from `AttackChain.steps[*].capabilities_used`.
 *   - `contributing_rule_ids` aggregates the rule ids from every supporting
 *     finding on the chain (from `ChainEvidence.supporting_findings`).
 *   - `mitigations` is flattened from `AttackChain.mitigations[*].description`
 *     in production wiring.
 */
export interface AttackChainRow {
  /** Database row id (uuid). */
  id: string;
  /** Kill-chain template identifier — constrained to the seven KCs. */
  template_id: KCId;
  /** Scan row this chain was synthesized from. */
  scan_id: string;
  /**
   * Pre-computed composite severity from the attack-graph scorer. Used for
   * stable ordering (descending) and rendered in the narrative header.
   * Range: 0.0..1.0 (matches `ExploitabilityScore.overall`).
   */
  severity_score: number;
  /** Rule ids that fired contributing to this chain (deduplicated upstream). */
  contributing_rule_ids: string[];
  /** Edge sequence — each element is one link in the chain path. */
  edge_path: string[];
  /** Pre-computed mitigations (one description per link, human-readable). */
  mitigations: string[];
  /** Chain synthesis timestamp (ISO 8601). */
  synthesized_at: string;
}

/**
 * Curated mapping declared in `data/kc-cve-mapping.ts`.
 *
 * Every KC must have an entry even when Phase 4 has no exemplar evidence —
 * declare `cve_evidence_ids: []` with a `// GAP` comment in that case.
 * This honesty lets regulators distinguish "no CVE published yet" from
 * "we forgot to map it".
 */
export interface KillChainPattern {
  kc_id: KCId;
  /** Human-readable chain name (matches the attack-graph template `name`). */
  name: string;
  /**
   * Regulator-friendly description — one paragraph, plain English, no
   * jargon. Rendered verbatim inside the generated narrative.
   */
  description: string;
  /**
   * Phase 4 corpus case ids exemplifying this chain class.
   *
   * Format-validated at test time:
   *   CVE-YYYY-NNNN (≥4 digit suffix) OR research-<kebab-case>.
   *
   * MAY be empty (declare `// GAP` comment) when no Phase 4 case
   * exemplifies the chain yet.
   */
  cve_evidence_ids: string[];
  /** Default mitigations for this chain class — deduplicated with the per-row mitigations by the synthesizer. */
  default_mitigations: string[];
}
