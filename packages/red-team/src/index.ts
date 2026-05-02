export { AccuracyRunner } from "./runner.js";
export {
  formatTextReport,
  formatJsonReport,
  formatHtmlReport,
  printSummary,
} from "./reporter.js";
export { ALL_FIXTURES, getFixturesForRule } from "./fixtures/index.js";
export type {
  RuleFixture,
  RuleFixtureSet,
  FixtureResult,
  RuleAccuracy,
  AccuracyReport,
  CategoryAccuracy,
} from "./types.js";

// ── CVE replay corpus (Phase 4) ──────────────────────────────────────────────
// Re-exported so downstream packages (notably @mcp-sentinel/compliance-reports
// kill-chain synthesizer, Phase 5) can consume the Phase 4 corpus without
// reaching into deep sub-paths. The loader (`loadCases`) triggers side-effect
// imports on `cases/index.ts` to populate the registry.
export {
  loadCases,
  getRegisteredCases,
  registerCVECase,
  clearRegistry,
  hasCase,
  DEFAULT_MANIFEST_PATH,
  loadManifestIds,
} from "./cve-corpus/index.js";
export type {
  CVECaseKind,
  CVEExpectedRule,
  CVEFixture,
  CVEReplayCase,
  CVECaseResult,
  CVECorpusReport,
} from "./cve-corpus/index.js";

// ── Public corpus manifest ─────────────────────────────────────────────────
// Aggregates per-rule fixture counts + CVE replays so consumers (e.g. the API
// layer rendering "tested against N adversarial fixtures + M CVE replays")
// can prove coverage without reaching into deep package paths.
//
// The cve-corpus uses side-effect imports — `getCorpusManifest()` triggers
// `loadCases()` on first call and memoises the result for the process lifetime.

import { ALL_FIXTURES } from "./fixtures/index.js";
import type { CVECaseKind } from "./cve-corpus/index.js";
import { loadCases, getRegisteredCases } from "./cve-corpus/index.js";

export interface RuleCorpusEntry {
  fixture_count: number;
  cve_replays: string[];
}

export type CorpusManifest = Record<string, RuleCorpusEntry>;

let _manifestCache: CorpusManifest | null = null;

export async function getCorpusManifest(): Promise<CorpusManifest> {
  if (_manifestCache) return _manifestCache;

  await loadCases();

  const manifest: CorpusManifest = {};

  for (const set of ALL_FIXTURES) {
    manifest[set.rule_id] = {
      fixture_count: set.fixtures.length,
      cve_replays: [],
    };
  }

  for (const c of getRegisteredCases()) {
    for (const expected of c.expected_rules) {
      const entry =
        manifest[expected.rule_id] ??
        (manifest[expected.rule_id] = { fixture_count: 0, cve_replays: [] });
      if (!entry.cve_replays.includes(c.id)) {
        entry.cve_replays.push(c.id);
      }
    }
  }

  _manifestCache = manifest;
  return manifest;
}

// ── Public CVE validation index ────────────────────────────────────────────
// The corpus manifest above keys `rule_id → cve_replays: string[]` (just IDs).
// This richer index keys `rule_id → CveReplayValidation[]` with the case
// metadata (title, source url, disclosure date, CVSS, kind) so the API layer
// can render a "validated against CVE-2025-6514: mcp-remote OS command
// injection" pill without re-fetching anything else.
//
// The shape is intentionally the public surface — both the api package and
// future SDK consumers read this. Internal-only fields (rationale, fixtures,
// expected_rules) are not exposed.

export interface CveReplayValidation {
  /** "CVE-YYYY-NNNN" for cve-kind, "research-kebab-id" for research-kind. */
  id: string;
  kind: CVECaseKind;
  title: string;
  source_url: string;
  /** ISO 8601 (YYYY-MM-DD). */
  disclosed: string;
  cvss_v3: number | null;
  /** Asserted minimum severity for this rule on the unpatched fixture. */
  min_severity: string;
}

export type CveValidationIndex = Record<string, CveReplayValidation[]>;

let _validationIndexCache: CveValidationIndex | null = null;

/**
 * Build (and memoise) the rule_id → CveReplayValidation[] inverse index
 * by iterating the registered CVE corpus cases. Each rule the case lists
 * under `expected_rules` becomes a validation entry for that rule.
 *
 * Memoised for the process lifetime — the registry is loaded once via
 * `loadCases()` and the case set is immutable.
 */
export async function getCveValidationIndex(): Promise<CveValidationIndex> {
  if (_validationIndexCache) return _validationIndexCache;

  await loadCases();

  const index: CveValidationIndex = {};
  for (const c of getRegisteredCases()) {
    for (const expected of c.expected_rules) {
      const entry: CveReplayValidation = {
        id: c.id,
        kind: c.kind,
        title: c.title,
        source_url: c.source_url,
        disclosed: c.disclosed,
        cvss_v3: typeof c.cvss_v3 === "number" ? c.cvss_v3 : null,
        min_severity: expected.min_severity,
      };
      const bucket = index[expected.rule_id] ?? (index[expected.rule_id] = []);
      // Dedupe by case id — multiple expected_rules entries from the same
      // case for the same rule_id would otherwise double-count.
      if (!bucket.some((b) => b.id === entry.id)) {
        bucket.push(entry);
      }
    }
  }
  // Stable order: cve-kind first (by id), then research-kind (by id). Auditors
  // expect canonical CVE rows above research-attack rows.
  for (const ruleId of Object.keys(index)) {
    index[ruleId]!.sort((a, b) => {
      if (a.kind !== b.kind) return a.kind === "cve" ? -1 : 1;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });
  }

  _validationIndexCache = index;
  return index;
}

/** Test-only: drop the memoised index so a hermetic test can rebuild. */
export function _resetCveValidationIndexForTests(): void {
  _validationIndexCache = null;
}
