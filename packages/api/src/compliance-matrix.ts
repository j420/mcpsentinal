/**
 * Compliance posture aggregate + per-finding framework cross-walk.
 *
 * Cluster B inventions #3 (Framework Posture Matrix) and #8 (per-finding
 * framework cross-walk) from `/root/.claude/plans/have-a-go-through-valiant-lollipop.md`.
 *
 * The route handlers in `server.ts` stay thin: they delegate to
 * `buildComplianceMatrix()` (here) for the aggregate endpoint and to
 * `getFrameworkControlsForRule()` (here) for the per-finding cross-walk.
 *
 * Why a separate file:
 *   - Keeps route handlers in `server.ts` declarative.
 *   - Centralises the rule→controls reverse index that `findings`
 *     responses rely on, so the index is built (and memoised) exactly
 *     once per process — not per request, not per finding.
 *   - Lets tests exercise the pure helper directly without booting the
 *     Express app.
 */

import {
  buildReport,
  FRAMEWORK_IDS,
  getAllFrameworks,
  type FrameworkId,
  type ReportInputFinding,
} from "@mcp-sentinel/compliance-reports";
import type {
  ComplianceControlCounts,
  ComplianceFrameworkDownloadPaths,
  ComplianceFrameworkMatrixEntry,
  ComplianceMatrixResponse,
  CoverageBand,
  Finding,
  FrameworkControlMapping,
  Server,
} from "@mcp-sentinel/database";

// ─── Coverage band heuristic ────────────────────────────────────────────────
// Mirrors `deriveCoverage()` in `compliance-report-routes.ts` so the matrix
// shows the same band the per-framework signed reports do. We deliberately
// duplicate (rather than import) because the signed-report module lives at
// the route-handler tier — pulling it in here would invert the layering.
function deriveCoverageBand(findingsCount: number): CoverageBand {
  if (findingsCount === 0) return "minimal";
  if (findingsCount < 5) return "low";
  if (findingsCount < 20) return "medium";
  return "high";
}

function deriveCoverageRatio(band: CoverageBand): number {
  switch (band) {
    case "minimal": return 0.0;
    case "low": return 0.4;
    case "medium": return 0.7;
    case "high": return 0.95;
  }
}

const TECHNIQUES_RUN: readonly string[] = [
  "ast-taint",
  "capability-graph",
  "entropy",
  "linguistic-scoring",
  "schema-inference",
];

// ─── Per-rule reverse index ────────────────────────────────────────────────
// Built lazily (first call) and memoised at module scope. Subsequent calls
// are O(1) per finding row. Rebuilding once per process is correct because
// the framework registries are static TypeScript constants — they cannot
// change at runtime without a process restart.

let _ruleIndex: Map<string, FrameworkControlMapping[]> | null = null;

/**
 * Rule_id → list of (framework_id, control_id, control_title) tuples.
 * Returns an empty array for any rule_id that maps to zero controls
 * (an honest gap — not every rule has framework alignment).
 *
 * The internal map is shared across calls; never mutate the returned
 * arrays in place.
 */
export function getFrameworkControlsForRule(
  ruleId: string,
): FrameworkControlMapping[] {
  if (!_ruleIndex) {
    _ruleIndex = buildRuleToControlsIndex();
  }
  return _ruleIndex.get(ruleId) ?? [];
}

/**
 * Build the rule→controls reverse index over every framework's controls.
 * Exported so tests can exercise it without forcing module reload, and so
 * future endpoints can reuse the same shape.
 */
export function buildRuleToControlsIndex(): Map<string, FrameworkControlMapping[]> {
  const index = new Map<string, FrameworkControlMapping[]>();
  for (const framework of getAllFrameworks()) {
    for (const control of framework.controls) {
      for (const ruleId of control.assessor_rule_ids) {
        let bucket = index.get(ruleId);
        if (!bucket) {
          bucket = [];
          index.set(ruleId, bucket);
        }
        bucket.push({
          framework_id: framework.id,
          control_id: control.control_id,
          control_title: control.control_name,
        });
      }
    }
  }
  return index;
}

/** Test-only: drop the memoised index so a test can re-exercise the build path. */
export function _resetRuleIndexForTests(): void {
  _ruleIndex = null;
}

// ─── Findings → ReportInputFinding projection ───────────────────────────────
function toReportInputFinding(f: Finding): ReportInputFinding {
  return {
    id: f.id,
    rule_id: f.rule_id,
    severity: f.severity,
    evidence: f.evidence,
    confidence: f.confidence,
    remediation: f.remediation,
  };
}

// ─── Posture matrix assembly ────────────────────────────────────────────────

export interface BuildComplianceMatrixOptions {
  /**
   * Engine + rule set version stamped into the response. Mirrors the value
   * embedded in the per-framework signed reports so consumers can reconcile
   * matrix and signed pack at a glance.
   */
  rules_version: string;
  /**
   * Engine version. Reserved for future use (frontend currently does not
   * surface this on the matrix grid; included for parity with the signed
   * report assembly contract).
   */
  sentinel_version: string;
  /**
   * Stable assessment timestamp. The matrix endpoint passes the same value
   * the per-framework signed report would compute (newest finding's
   * created_at, or server.last_scanned_at, or null) so a regulator who
   * cross-references the matrix against the signed pack sees a single
   * coherent timestamp.
   *
   * Pass `null` when no scan exists; the response will reflect this in
   * `last_assessed_at`.
   */
  assessed_at: string | null;
}

/**
 * Assemble the Posture Matrix for one server, across every framework. Calls
 * `buildReport()` once per framework (7 in-memory passes over `findings`).
 *
 * NOT signed — the signed, HMAC-attested artifacts live at the per-framework
 * `/compliance/:framework.{json,html,pdf}` endpoints. This is a navigational
 * summary so the registry can render the matrix without 7 round-trips.
 */
export function buildComplianceMatrix(
  findings: Finding[],
  server: Pick<Server, "id" | "slug" | "name" | "github_url">,
  opts: BuildComplianceMatrixOptions,
): ComplianceMatrixResponse {
  const reportFindings = findings.map(toReportInputFinding);
  const coverageBand = deriveCoverageBand(findings.length);
  const coverageRatio = deriveCoverageRatio(coverageBand);

  // Stable scan_id for buildReport's required `server.scan_id` field. The
  // matrix endpoint does not surface scan_id, but buildReport requires it
  // for the per-framework signed report contract. Cluster B reviewer m1:
  // findings[0] is not guaranteed-newest at this layer (the DB query does
  // not sort), so we fold once over created_at to find the actual newest.
  // Falls back to the zero UUID when there are no findings (signed-report
  // assembly already handles this constant safely).
  const newestFinding = findings.reduce<typeof findings[number] | null>(
    (acc, f) => (acc === null || f.created_at > acc.created_at ? f : acc),
    null,
  );
  const scanId = newestFinding?.scan_id ?? "00000000-0000-0000-0000-000000000000";
  // Renderers + signers want a non-null timestamp string. The matrix
  // response surfaces null in `last_assessed_at` when no scan exists, but
  // buildReport itself needs *something* for the embedded timestamp inside
  // each per-framework report we build for our counts. We use the Unix
  // epoch as a deterministic fallback — the report bytes never leave this
  // function, so the placeholder is invisible to the caller.
  const assessedAtForBuild = opts.assessed_at ?? "1970-01-01T00:00:00.000Z";

  const entries: ComplianceFrameworkMatrixEntry[] = FRAMEWORK_IDS.map((fid) =>
    buildEntry(
      fid,
      server.slug,
      reportFindings,
      coverageBand,
      coverageRatio,
      scanId,
      server,
      assessedAtForBuild,
      opts,
    ),
  );

  return {
    server_slug: server.slug,
    server_name: server.name,
    last_assessed_at: opts.assessed_at,
    rules_version: opts.rules_version,
    frameworks: entries,
  };
}

function buildEntry(
  frameworkId: FrameworkId,
  slug: string,
  reportFindings: ReportInputFinding[],
  coverageBand: CoverageBand,
  coverageRatio: number,
  scanId: string,
  server: Pick<Server, "slug" | "name" | "github_url">,
  assessedAt: string,
  opts: BuildComplianceMatrixOptions,
): ComplianceFrameworkMatrixEntry {
  const report = buildReport({
    framework_id: frameworkId,
    server: {
      slug: server.slug,
      name: server.name,
      github_url: server.github_url,
      scan_id: scanId,
    },
    findings: reportFindings,
    coverage: {
      band: coverageBand,
      ratio: coverageRatio,
      techniques_run: [...TECHNIQUES_RUN],
    },
    rules_version: opts.rules_version,
    sentinel_version: opts.sentinel_version,
    kill_chains: [],
    assessed_at: assessedAt,
  });

  const counts: ComplianceControlCounts = {
    met: report.summary.met,
    partial: report.summary.partial,
    unmet: report.summary.unmet,
    not_applicable: report.summary.not_applicable,
    total: report.controls.length,
  };

  return {
    framework_id: frameworkId,
    framework_name: report.framework.name,
    framework_version: report.framework.version,
    controls: counts,
    overall_status: deriveOverallStatus(counts),
    coverage_band: coverageBand,
    download_paths: buildDownloadPaths(slug, frameworkId),
  };
}

/**
 * Flatten the four per-status counts into a single `met | partial | unmet
 * | not_applicable` headline status used by the matrix grid cell. The
 * compliance-reports `OverallStatus` (`compliant | non_compliant |
 * partially_compliant | insufficient_evidence`) is the regulator-facing
 * vocabulary embedded in the SIGNED reports — but the matrix headline is
 * about CONTROL counts, not framework certification, so we use the same
 * vocabulary as a single ControlStatus to keep the UI grid consistent
 * (each cell already shows met/partial/unmet/n.a. counts; the overall
 * status is just the highest-severity bucket present).
 */
function deriveOverallStatus(
  counts: ComplianceControlCounts,
): ComplianceFrameworkMatrixEntry["overall_status"] {
  if (counts.unmet > 0) return "unmet";
  if (counts.partial > 0) return "partial";
  if (counts.met > 0) return "met";
  return "not_applicable";
}

/**
 * Build relative paths (no host) for the per-framework signed-pack
 * endpoints. The frontend appends these to its own `apiUrl` env var.
 *
 * We URI-encode the slug so a slug containing a hyphen or underscore is
 * forwarded verbatim, but a malformed slug that somehow reached this
 * function (the route handler already validates) cannot break the URL.
 */
function buildDownloadPaths(
  slug: string,
  frameworkId: FrameworkId,
): ComplianceFrameworkDownloadPaths {
  const base = `/api/v1/servers/${encodeURIComponent(slug)}/compliance/${frameworkId}`;
  return {
    json: `${base}.json`,
    html: `${base}.html`,
    pdf: `${base}.pdf`,
    badge_svg: `${base}/badge.svg`,
  };
}
