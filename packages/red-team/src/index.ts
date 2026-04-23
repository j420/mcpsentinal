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
