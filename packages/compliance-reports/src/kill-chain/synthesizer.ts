/**
 * Kill-chain narrative synthesizer.
 *
 * Pure function. Inputs: persisted `attack_chains` rows + Phase 4 corpus.
 * Output: an array of `KillChainNarrative` records ready to be inlined
 * into a `ComplianceReport.kill_chains`.
 *
 * No DB access, no file I/O, no LLM — production wiring in
 * `packages/attack-graph` CLI / `packages/api` endpoints translates
 * DB rows into `AttackChainRow` and loads the Phase 4 registry via
 * `loadCases()`; tests pass synthetic inputs.
 */
import type { CVEReplayCase } from "@mcp-sentinel/red-team";
import { buildNarrative, uniqSorted } from "./narrative-builder.js";
import { KILL_CHAIN_TO_CVE_PATTERNS } from "./data/kc-cve-mapping.js";
import type {
  AttackChainRow,
  KCId,
  KillChainNarrative,
  KillChainPattern,
} from "./types.js";

export interface SynthesizeInput {
  /** Persisted attack_chains rows, projected onto the synthesizer-facing shape. */
  chains: AttackChainRow[];
  /**
   * Full Phase 4 corpus. Production code obtains this via
   * `loadCases()` from `@mcp-sentinel/red-team`; unit tests pass
   * synthetic arrays. The synthesizer treats this as the source of
   * truth — any `cve_evidence_id` declared in the mapping but NOT
   * present in the corpus is silently dropped for that chain's output
   * (the integration test asserts zero drops against the real registry,
   * so discrepancies are caught at build time, not in production).
   */
  cve_corpus: CVEReplayCase[];
}

/**
 * Look up a chain's pattern — typed access guarded by `KCId`.
 */
function getPattern(templateId: KCId): KillChainPattern {
  return KILL_CHAIN_TO_CVE_PATTERNS[templateId];
}

/**
 * Filter a pattern's `cve_evidence_ids` against the provided corpus,
 * retaining only ids that are actually registered. This makes the
 * output self-describing: if a case is removed upstream, the narrative
 * drops silently instead of citing a missing exemplar.
 */
function resolveCVEIds(
  pattern: KillChainPattern,
  corpusIds: Set<string>
): string[] {
  return pattern.cve_evidence_ids.filter((id) => corpusIds.has(id));
}

/**
 * Stable ordering: severity descending, then `kc_id` ascending. Deterministic
 * for regulator re-generation (same input bytes → same output order).
 */
function compareNarratives(a: KillChainNarrative, b: KillChainNarrative): number {
  if (b.severity_score !== a.severity_score) {
    return b.severity_score - a.severity_score;
  }
  return a.kc_id.localeCompare(b.kc_id);
}

export function synthesizeKillChains(
  input: SynthesizeInput
): KillChainNarrative[] {
  const corpusIds = new Set(input.cve_corpus.map((c) => c.id));

  const narratives: KillChainNarrative[] = input.chains.map((chain) => {
    const pattern = getPattern(chain.template_id);
    const resolvedCVEIds = resolveCVEIds(pattern, corpusIds);

    // Inject the resolved (corpus-backed) ids into a pattern clone so the
    // narrative builder emits only exemplars that really exist. We keep the
    // ORIGINAL pattern object pristine (mapping is shared state).
    const effectivePattern: KillChainPattern = {
      ...pattern,
      cve_evidence_ids: resolvedCVEIds,
    };

    const narrativeText = buildNarrative(chain, effectivePattern);

    const mergedMitigations = uniqSorted([
      ...chain.mitigations,
      ...pattern.default_mitigations,
    ]);
    const mergedRuleIds = uniqSorted(chain.contributing_rule_ids);

    return {
      kc_id: pattern.kc_id,
      name: pattern.name,
      severity_score: chain.severity_score,
      narrative: narrativeText,
      contributing_rule_ids: mergedRuleIds,
      cve_evidence_ids: [...resolvedCVEIds].sort(),
      mitigations: mergedMitigations,
    };
  });

  return narratives.sort(compareNarratives);
}
