/**
 * Deterministic narrative builder.
 *
 * Pure function — no LLM (ADR-006), no randomness, no I/O. Given an
 * `AttackChainRow` and its `KillChainPattern`, assembles a multi-paragraph
 * regulator-friendly narrative string that renderers emit verbatim.
 *
 * The output structure is fixed so regression tests can assert section
 * presence and so the HTML/PDF renderers can visually style the same
 * sections across reports.
 */
import type { AttackChainRow, KillChainPattern } from "./types.js";

/**
 * Format a 0.0..1.0 severity score as a two-digit decimal string (e.g.
 * 0.83). Deterministic — no `toFixed` locale quirks because we clamp and
 * format ourselves.
 */
function formatSeverity(score: number): string {
  const clamped = Math.max(0, Math.min(1, score));
  // Round to 2 decimals deterministically.
  const rounded = Math.round(clamped * 100) / 100;
  // Always produce exactly two decimals, even for e.g. 0.5 → "0.50".
  return rounded.toFixed(2);
}

function renderEdgePath(edgePath: string[]): string {
  if (edgePath.length === 0) {
    return "No ordered step sequence was recorded for this chain.";
  }
  const lines = edgePath.map((step, idx) => `${idx + 1}. ${step}`);
  return lines.join("\n");
}

function renderContributingRules(ruleIds: string[]): string {
  if (ruleIds.length === 0) {
    return "No single-server detection rules contributed to this chain.";
  }
  const sorted = [...ruleIds].sort();
  return `Detection rules that fired contributing to this chain: ${sorted.join(", ")}.`;
}

function renderCVEEvidence(cveIds: string[]): string {
  if (cveIds.length === 0) {
    return (
      "No published CVE replays in Phase 4 directly exemplify this chain class yet " +
      "(gap tracked for Phase 6 corpus expansion)."
    );
  }
  const sorted = [...cveIds].sort();
  const count = sorted.length;
  const plural = count === 1 ? "replay" : "replays";
  return (
    `This attack class has been demonstrated in the wild by ${count} CVE/research ` +
    `${plural} in MCP Sentinel's Phase 4 corpus: ${sorted.join(", ")}. ` +
    "Each exemplifies the same source → sink pattern observed here."
  );
}

function renderMitigations(mitigations: string[]): string {
  if (mitigations.length === 0) {
    return "No mitigations were recorded for this chain.";
  }
  const lines = mitigations.map((m) => `- ${m}`);
  return lines.join("\n");
}

/**
 * Deduplicate + stably sort a string array. Used for rule-id lists and
 * mitigation lists where the same value may arrive from multiple sources
 * (chain row + pattern defaults).
 */
function uniqSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

/**
 * Build a full multi-paragraph narrative string for one kill-chain row.
 *
 * Structure (asserted by `__tests__/narrative-builder.test.ts`):
 *   - Header line with KC id, name, severity score.
 *   - Pattern description paragraph.
 *   - Numbered step list from `edge_path`.
 *   - Contributing rules sentence.
 *   - CVE-evidence sentence OR honest-gap sentence.
 *   - Mitigations bullet list.
 */
export function buildNarrative(
  chain: AttackChainRow,
  pattern: KillChainPattern
): string {
  const severity = formatSeverity(chain.severity_score);
  const header = `This server matched kill chain ${pattern.kc_id} ("${pattern.name}"), severity ${severity}.`;

  const description = pattern.description;

  const chainSection = [
    "The chain proceeds as follows:",
    renderEdgePath(chain.edge_path),
  ].join("\n");

  const rulesSection = renderContributingRules(chain.contributing_rule_ids);

  const cveSection = renderCVEEvidence(pattern.cve_evidence_ids);

  const mergedMitigations = uniqSorted([
    ...chain.mitigations,
    ...pattern.default_mitigations,
  ]);
  const mitigationsSection = [
    "Recommended mitigations:",
    renderMitigations(mergedMitigations),
  ].join("\n");

  return [
    header,
    "",
    description,
    "",
    chainSection,
    "",
    rulesSection,
    "",
    cveSection,
    "",
    mitigationsSection,
  ].join("\n");
}

// Exported helpers — useful for unit tests and for the synthesizer's
// list-merging logic.
export { uniqSorted };
