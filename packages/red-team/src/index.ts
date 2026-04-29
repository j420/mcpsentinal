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
