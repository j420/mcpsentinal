/**
 * Per-finding detection-quality footer (Cluster C invention #4).
 *
 * Lookup function `getDetectionQualityForRule(rule_id)` is wired into BOTH
 * `GET /api/v1/servers/:slug` and `GET /api/v1/servers/:slug/findings` so
 * the page can render the regulator-grade footer:
 *
 *   "Backed by N red-team fixtures, CVE-x,y,z, precision p, recall r;
 *    last validated ${last_validated_at}."
 *
 * Two distinct empty states, both intentional:
 *
 *   1. The whole field is `null` → the rule is NOT YET WIRED into either
 *      validation source. Frontend renders "detection quality not yet
 *      measured".
 *
 *   2. The field is non-null but `precision`/`recall`/`last_validated_at`
 *      are null and `fixture_count: 0`/`cve_replay_ids: []` → the rule is
 *      wired but has no validation data on file yet. Frontend renders
 *      "no validations on file" rather than hiding.
 *
 * Why a separate file:
 *   - Mirrors the structure of `compliance-matrix.ts` (Cluster B) — pure
 *     helper module + memoised reverse index built lazily on first call.
 *   - Lets tests exercise the helper directly without booting Express.
 *   - Keeps the route handlers in `server.ts` thin (per packages/api/CLAUDE.md).
 *
 * Data sources (both lazy, both memoised at module scope):
 *   1. `getCorpusManifest()` from `@mcp-sentinel/red-team` — provides
 *      `fixture_count` and `cve_replay_ids` per rule_id. Already lazy-loaded
 *      in `server.ts` to avoid blocking boot on the analyzer transitive dep.
 *   2. `docs/accuracy/latest.json` — provides `precision`, `recall`, and
 *      `last_validated_at`. Resolved on a best-effort basis from a known
 *      relative path. The file ships at the repo root and is regenerated
 *      by `pnpm red-team:dashboard`. If the file is missing at runtime
 *      (e.g. the docs/ tree is not copied into the production container),
 *      precision/recall/last_validated_at degrade to null but the rest
 *      of the field still populates from the corpus manifest.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { CorpusManifest } from "@mcp-sentinel/red-team";
import type { DetectionQuality } from "@mcp-sentinel/database";

// Resolve docs/accuracy/latest.json relative to this source file. Going
// up four levels lands at the repo root: src/ → packages/api/ → packages/ → repo.
// `import.meta.url` is correct under TS/Node ESM. Wrapped in a function
// so a test can monkey-patch the resolution path if it ever needs to.
//
// Important: this file is read SYNCHRONOUSLY at first lookup so the
// reverse index is fully populated before any finding is augmented.
// Async fs is unnecessary — the file is small (~80 KB) and we only
// read it once per process.
function defaultAccuracyPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, "..", "..", "..", "docs", "accuracy", "latest.json");
}

interface AccuracyRow {
  rule_id: string;
  measured_precision: number;
  measured_recall: number;
}

interface AccuracySnapshot {
  generated_at: string;
  rules: AccuracyRow[];
}

let _index: Map<string, DetectionQuality> | null = null;
let _corpusPromise: Promise<CorpusManifest> | null = null;

/**
 * Lazily load + memoise the corpus manifest. Mirrors the lazy-load
 * pattern in `server.ts` so the api package doesn't pay the analyzer
 * import cost at boot when no `/findings` request is in flight.
 */
function loadCorpus(): Promise<CorpusManifest> {
  if (!_corpusPromise) {
    _corpusPromise = import("@mcp-sentinel/red-team")
      .then((mod) => mod.getCorpusManifest())
      .catch(() => ({}));
  }
  return _corpusPromise;
}

/** Read the dashboard accuracy snapshot. Returns null if unreadable. */
function readAccuracySnapshot(): AccuracySnapshot | null {
  try {
    const raw = readFileSync(defaultAccuracyPath(), "utf-8");
    const parsed = JSON.parse(raw) as unknown;
    if (
      parsed &&
      typeof parsed === "object" &&
      Array.isArray((parsed as { rules?: unknown }).rules)
    ) {
      return parsed as AccuracySnapshot;
    }
    return null;
  } catch {
    // Missing file or parse error — degrade gracefully. The corpus
    // manifest still drives fixture_count + cve_replay_ids; precision,
    // recall, and last_validated_at simply remain null.
    return null;
  }
}

/**
 * Build the reverse index keyed by rule_id. Sync because both inputs
 * (corpus manifest + accuracy snapshot) are already loaded by the
 * caller before reaching here.
 */
function buildIndex(
  corpus: CorpusManifest,
  snapshot: AccuracySnapshot | null,
): Map<string, DetectionQuality> {
  const index = new Map<string, DetectionQuality>();
  const generatedAt = snapshot?.generated_at ?? null;

  // Seed from corpus first — every rule_id with a fixture or CVE replay.
  for (const [ruleId, entry] of Object.entries(corpus)) {
    index.set(ruleId, {
      precision: null,
      recall: null,
      fixture_count: entry.fixture_count,
      cve_replay_ids: [...entry.cve_replays],
      last_validated_at: null,
    });
  }

  // Layer the accuracy snapshot on top — populates precision, recall,
  // and last_validated_at for any rule that appears in BOTH sources OR
  // only in the snapshot.
  if (snapshot && Array.isArray(snapshot.rules)) {
    for (const row of snapshot.rules) {
      if (!row || typeof row.rule_id !== "string") continue;
      const existing = index.get(row.rule_id);
      const next: DetectionQuality = existing
        ? { ...existing }
        : {
            precision: null,
            recall: null,
            fixture_count: 0,
            cve_replay_ids: [],
            last_validated_at: null,
          };
      next.precision =
        typeof row.measured_precision === "number" ? row.measured_precision : null;
      next.recall =
        typeof row.measured_recall === "number" ? row.measured_recall : null;
      next.last_validated_at = generatedAt;
      index.set(row.rule_id, next);
    }
  }

  return index;
}

let _indexBuildPromise: Promise<Map<string, DetectionQuality>> | null = null;

function getOrBuildIndex(): Promise<Map<string, DetectionQuality>> {
  if (_index) return Promise.resolve(_index);
  if (!_indexBuildPromise) {
    _indexBuildPromise = loadCorpus().then((corpus) => {
      const snapshot = readAccuracySnapshot();
      const built = buildIndex(corpus, snapshot);
      _index = built;
      return built;
    });
  }
  return _indexBuildPromise;
}

/**
 * Synchronous lookup. Returns null when the index hasn't been primed yet
 * (the first call returns null; subsequent calls return populated data
 * once `primeDetectionQualityIndex()` has resolved at least once).
 *
 * Route handlers should `await primeDetectionQualityIndex()` once per
 * request before mapping over findings, then call this synchronously
 * from the map. This matches `getFrameworkControlsForRule()` in
 * `compliance-matrix.ts` exactly.
 */
export function getDetectionQualityForRule(
  ruleId: string,
): DetectionQuality | null {
  if (!_index) return null;
  return _index.get(ruleId) ?? null;
}

/**
 * Prime the reverse index. Idempotent — safe to call on every request;
 * after the first successful call returns immediately. Returns the
 * built index for callers that want a one-shot lookup.
 */
export async function primeDetectionQualityIndex(): Promise<
  Map<string, DetectionQuality>
> {
  return getOrBuildIndex();
}

// ─── Test-only ──────────────────────────────────────────────────────────────
// Exported with a leading underscore so they're clearly NOT part of the
// public API. Tests use these to exercise different empty-state paths.

/** Drop the memoised index + corpus promise so a test can rebuild from scratch. */
export function _resetDetectionQualityIndexForTests(): void {
  _index = null;
  _indexBuildPromise = null;
  _corpusPromise = null;
}

/**
 * Force a specific index map for a test. Skips both fs reads and the
 * red-team import entirely — useful for hermetic tests that want to
 * pin precision/recall/cve_replay_ids/etc. to specific values.
 */
export function _setDetectionQualityIndexForTests(
  index: Map<string, DetectionQuality>,
): void {
  _index = index;
  _indexBuildPromise = Promise.resolve(index);
}
