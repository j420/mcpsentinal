/**
 * Drift & History helper (Cluster C invention #8).
 *
 * Surfaces G6 (rug-pull) + I14 (rolling capability drift) signals as a
 * regulator-grade headline list, plus a compact score history.
 *
 * Why a separate file:
 *   - Mirrors `compliance-matrix.ts` (Cluster B reference architecture):
 *     thin route handler in `server.ts` + pure helper here.
 *   - Lets tests exercise the diff + trend logic directly.
 *
 * Resilience: when there are fewer than 2 scans in the window,
 *   - `headlines: []`
 *   - `score_history` may be 0–1 entries
 *   - `trend: "insufficient_data"`
 * Frontend renders an explicit "not enough scan history yet" panel —
 * Cluster A/B lesson: empty state IS a feature.
 */

import type {
  DriftHeadline,
  DriftResponse,
  DriftScorePoint,
  DriftTrend,
} from "@mcp-sentinel/database";

// ─── Tool pin diff shape (mirrors @mcp-sentinel/analyzer::ToolPinDiff) ──────
//
// Re-declared locally so the api package does NOT take a workspace
// dependency on @mcp-sentinel/analyzer (which would pull all 164 rules
// at module load and slow API boot). The route handler will compute
// the diff from persisted fingerprints once the
// `NNN_add_tool_fingerprints.sql` migration ships and pass the
// already-computed diff in here. Test fixtures construct this shape
// directly.

interface ToolFingerprintLike {
  name: string;
  hash: string;
  field_hashes: {
    name: string;
    description: string;
    schema: string;
    annotations: string;
  };
}

export interface ToolPinDiffLike {
  changed: boolean;
  added: ToolFingerprintLike[];
  removed: ToolFingerprintLike[];
  modified: Array<{
    name: string;
    previous_hash: string;
    current_hash: string;
    changed_fields: Array<"description" | "schema" | "annotations">;
  }>;
  unchanged: number;
}

// ─── Trend computation ──────────────────────────────────────────────────────

/**
 * Threshold for "improving" / "degrading". A delta of <5 across the
 * window is "neutral" — registry scores routinely flicker by a couple
 * of points between scans without reflecting real movement.
 */
const TREND_THRESHOLD = 5;

/**
 * Compute the trend label from a score-history series.
 *
 * Inputs are expected sorted any direction (we sort here defensively).
 * Returns `"insufficient_data"` when fewer than 2 datapoints exist —
 * the contract treats this as a distinct UI state.
 */
export function computeTrend(scoreHistory: DriftScorePoint[]): DriftTrend {
  if (scoreHistory.length < 2) return "insufficient_data";
  // Ascending by scanned_at so [0] is earliest, [N-1] is latest.
  const sorted = [...scoreHistory].sort((a, b) =>
    a.scanned_at < b.scanned_at ? -1 : a.scanned_at > b.scanned_at ? 1 : 0,
  );
  const earliest = sorted[0]!.score;
  const latest = sorted[sorted.length - 1]!.score;
  const delta = latest - earliest;
  if (delta >= TREND_THRESHOLD) return "improving";
  if (delta <= -TREND_THRESHOLD) return "degrading";
  return "neutral";
}

// ─── Tool fingerprint diff → headlines ──────────────────────────────────────

/**
 * Diff two consecutive tool fingerprints into headline rows.
 *
 * Takes an already-computed `ToolPinDiffLike` rather than the two raw
 * pins so this module does not import `@mcp-sentinel/analyzer` (which
 * would pull all 164 rules at module load). The route handler computes
 * the diff via `diffToolPins()` from analyzer once the
 * `NNN_add_tool_fingerprints.sql` migration ships and the scanner
 * starts persisting `ServerToolPin` JSON onto each scan row.
 */
export function diffPinsToHeadlines(
  diff: ToolPinDiffLike,
  occurredAt: string,
): DriftHeadline[] {
  if (!diff.changed) return [];

  const headlines: DriftHeadline[] = [];

  for (const t of diff.added) {
    headlines.push({
      kind: "tool_added",
      severity_hint: "elevated",
      occurred_at: occurredAt,
      summary: clamp200(`New tool "${t.name}" added since previous scan.`),
      ref: { tool_name: t.name },
    });
  }
  for (const t of diff.removed) {
    headlines.push({
      kind: "tool_removed",
      severity_hint: "neutral",
      occurred_at: occurredAt,
      summary: clamp200(`Tool "${t.name}" removed since previous scan.`),
      ref: { tool_name: t.name },
    });
  }
  for (const m of diff.modified) {
    if (m.changed_fields.includes("description")) {
      headlines.push({
        kind: "tool_description_changed",
        severity_hint: "elevated",
        occurred_at: occurredAt,
        summary: clamp200(`Description changed on "${m.name}" — review for prompt-injection drift.`),
        ref: {
          tool_name: m.name,
          from: m.previous_hash.slice(0, 12),
          to: m.current_hash.slice(0, 12),
        },
      });
    }
    if (m.changed_fields.includes("schema") || m.changed_fields.includes("annotations")) {
      headlines.push({
        kind: "capability_added",
        severity_hint: "elevated",
        occurred_at: occurredAt,
        summary: clamp200(
          `${m.changed_fields.includes("annotations") ? "Annotations" : "Schema"} changed on "${m.name}" — capabilities may have shifted.`,
        ),
        ref: {
          tool_name: m.name,
          from: m.previous_hash.slice(0, 12),
          to: m.current_hash.slice(0, 12),
        },
      });
    }
  }

  return headlines;
}

/**
 * Cap a summary at 200 characters per the contract. Truncates with an
 * ellipsis so a regulator parsing the JSON can still tell the string
 * was longer.
 */
function clamp200(s: string): string {
  if (s.length <= 200) return s;
  return s.slice(0, 197) + "...";
}

// ─── Score-change headlines ─────────────────────────────────────────────────

/**
 * Emit `score_changed` headlines from a score-history series. One
 * headline per pair of consecutive points where the delta meets the
 * trend threshold.
 *
 * Inputs assumed already trimmed to the requested window. Sorted
 * ascending by scanned_at internally so the headlines fire in the
 * order the changes occurred.
 */
export function scoreHistoryToHeadlines(
  scoreHistory: DriftScorePoint[],
): DriftHeadline[] {
  if (scoreHistory.length < 2) return [];
  const sorted = [...scoreHistory].sort((a, b) =>
    a.scanned_at < b.scanned_at ? -1 : a.scanned_at > b.scanned_at ? 1 : 0,
  );

  const headlines: DriftHeadline[] = [];
  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1]!;
    const curr = sorted[i]!;
    const delta = curr.score - prev.score;
    if (Math.abs(delta) < TREND_THRESHOLD) continue;
    const direction: "improving" | "degrading" =
      delta > 0 ? "improving" : "degrading";
    headlines.push({
      kind: "score_changed",
      severity_hint: direction,
      occurred_at: curr.scanned_at,
      summary: clamp200(
        `Score moved from ${prev.score} to ${curr.score} (${delta > 0 ? "+" : ""}${delta}).`,
      ),
      ref: {
        from: String(prev.score),
        to: String(curr.score),
      },
    });
  }
  return headlines;
}

// ─── Top-level assembly ─────────────────────────────────────────────────────

export interface BuildDriftInput {
  serverSlug: string;
  windowDays: number;
  /**
   * Score-history points already trimmed to the requested window by the
   * caller, OR the full history (we trim again here for safety).
   * Unsorted — we sort defensively.
   */
  scoreHistory: DriftScorePoint[];
  /**
   * Tool-fingerprint diff headlines. The persistence migration isn't
   * shipped yet; route handlers pass `[]` for now. Once
   * `NNN_add_tool_fingerprints.sql` lands the scanner pipeline writes
   * `ServerToolPin` JSON onto each scan row and the route handler
   * calls `diffPinsToHeadlines()` between consecutive scans.
   */
  fingerprintHeadlines: DriftHeadline[];
}

/**
 * Assemble the `DriftResponse`. Pure — no IO, no DB, no fs.
 *
 * Behaviour:
 *   - sorts scoreHistory ascending by scanned_at (oldest first)
 *   - merges fingerprintHeadlines + score-change headlines, ordered by
 *     occurred_at descending (most recent first — the headlines list
 *     reads top-to-bottom as "what changed most recently")
 *   - computes trend from first vs last point in the window
 *   - on insufficient_data, headlines is forced to `[]` so the frontend
 *     never sees "tool added" without a corresponding history point to
 *     anchor it
 */
export function buildDriftResponse(input: BuildDriftInput): DriftResponse {
  const sorted = [...input.scoreHistory].sort((a, b) =>
    a.scanned_at < b.scanned_at ? -1 : a.scanned_at > b.scanned_at ? 1 : 0,
  );
  const trend = computeTrend(sorted);

  // When we don't have enough data, suppress headlines entirely. The
  // frontend's "insufficient_data" panel is the right UI state and a
  // headline list with no anchoring score history is misleading.
  const headlines: DriftHeadline[] =
    trend === "insufficient_data"
      ? []
      : [
          ...input.fingerprintHeadlines,
          ...scoreHistoryToHeadlines(sorted),
        ].sort((a, b) =>
          a.occurred_at < b.occurred_at ? 1 : a.occurred_at > b.occurred_at ? -1 : 0,
        );

  return {
    server_slug: input.serverSlug,
    window_days: input.windowDays,
    headlines,
    score_history: sorted,
    trend,
  };
}
