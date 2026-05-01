/**
 * Risk Boundary aggregate (Cluster C invention #3).
 *
 * Surfaces a server's involvement in cross-server risk patterns
 * (P01-P12 from `packages/risk-matrix`) and kill chains
 * (KC01-KC07 from `packages/attack-graph`).
 *
 * Why a separate file:
 *   - Mirrors `compliance-matrix.ts` (Cluster B reference architecture):
 *     thin route handler in `server.ts` + pure helper here.
 *   - Lets tests exercise the helper directly without booting Express.
 *   - Centralises the pattern_id → name/description reverse index so it
 *     is built (and memoised) exactly once per process.
 *
 * Empty-state contract: when neither `risk_edges` nor `attack_chains`
 * have ever been computed for a server, both response arrays are empty.
 * The frontend renders that as "no cross-config exposure on file" —
 * Cluster A/B lesson: empty state IS a feature.
 */

import { ALL_PATTERNS } from "@mcp-sentinel/risk-matrix";
import type {
  RiskBoundaryKillChain,
  RiskBoundaryPattern,
  RiskBoundaryPatternPairing,
  RiskBoundaryResponse,
  Server,
} from "@mcp-sentinel/database";

// ─── Pattern catalogue (P01-P12) ────────────────────────────────────────────
// Built lazily from `ALL_PATTERNS` so a future pattern addition surfaces
// here automatically. Memoised at module scope — the catalogue is a
// static TypeScript constant; it cannot change at runtime without a
// process restart.

interface PatternMeta {
  pattern_id: string;
  pattern_name: string;
  pattern_summary: string;
  severity: "critical" | "high" | "medium" | "low";
}

let _patternMetaIndex: Map<string, PatternMeta> | null = null;

function getPatternMeta(patternId: string): PatternMeta | null {
  if (!_patternMetaIndex) {
    _patternMetaIndex = new Map();
    for (const p of ALL_PATTERNS) {
      _patternMetaIndex.set(p.id, {
        pattern_id: p.id,
        pattern_name: p.name,
        pattern_summary: p.description,
        severity: p.severity,
      });
    }
  }
  return _patternMetaIndex.get(patternId) ?? null;
}

/** Test-only: clear the memoised pattern metadata index. */
export function _resetPatternMetaIndexForTests(): void {
  _patternMetaIndex = null;
}

// ─── Risk-edge row → response shape ─────────────────────────────────────────
//
// Inputs come from `db.getRiskEdgesForServer(serverId)` — the persisted
// edge row carries:
//   { from_server_id, from_server_slug, from_server_name,
//     to_server_id,   to_server_slug,   to_server_name,
//     edge_type, pattern_id, severity, description, … }
//
// We DO NOT trust the persisted `severity` for the matrix headline —
// that's a per-edge field and may differ from the pattern's canonical
// severity. The frontend asks for the pattern's severity; we look that
// up from `ALL_PATTERNS`.

export interface PersistedRiskEdgeRow {
  from_server_id: string;
  from_server_name: string;
  from_server_slug: string;
  to_server_id: string;
  to_server_name: string;
  to_server_slug: string;
  edge_type: string;
  pattern_id: string;
  severity: string;
  description: string;
  owasp_category: string | null;
  mitre_technique: string | null;
  detected_at: string;
}

// ─── Kill-chain row → response shape ─────────────────────────────────────────

export interface PersistedAttackChainRow {
  id: string;
  chain_id: string;
  config_id: string;
  kill_chain_id: string;
  kill_chain_name: string;
  steps: unknown[];
  exploitability_overall: number;
  exploitability_rating: string;
  narrative: string;
  mitigations: unknown[];
  owasp_refs: string[];
  mitre_refs: string[];
  created_at: Date;
}

// ─── Pattern aggregation ────────────────────────────────────────────────────
//
// Each persisted edge row carries a `pattern_id`. We group edges by
// pattern_id to produce one `RiskBoundaryPattern` entry per fired
// pattern. Then we extract the OTHER server (the one that isn't this
// server) from each edge as a sample pairing, capped at 5 distinct
// slugs for UX.

export function buildPatternsFromRiskEdges(
  serverId: string,
  edges: PersistedRiskEdgeRow[],
): RiskBoundaryPattern[] {
  // Bucket edges by pattern_id, deduplicating sample pairings by slug.
  type Bucket = {
    meta: PatternMeta;
    pairings: Map<string, RiskBoundaryPatternPairing>;
  };
  const buckets = new Map<string, Bucket>();

  for (const edge of edges) {
    const meta = getPatternMeta(edge.pattern_id);
    if (!meta) continue; // unknown pattern_id — skip rather than misrepresent
    let bucket = buckets.get(edge.pattern_id);
    if (!bucket) {
      bucket = { meta, pairings: new Map() };
      buckets.set(edge.pattern_id, bucket);
    }
    // The "other" server in this edge is whichever side != serverId.
    // If both sides match (self-edge — should never happen but be defensive),
    // skip rather than emit a pairing of the server with itself.
    if (edge.from_server_id !== serverId) {
      bucket.pairings.set(edge.from_server_slug, {
        slug: edge.from_server_slug,
        name: edge.from_server_name,
      });
    } else if (edge.to_server_id !== serverId) {
      bucket.pairings.set(edge.to_server_slug, {
        slug: edge.to_server_slug,
        name: edge.to_server_name,
      });
    }
  }

  // Materialise into the response shape, preserving deterministic order
  // (sort by pattern_id so the response is stable across requests).
  const patterns: RiskBoundaryPattern[] = [];
  const sortedIds = [...buckets.keys()].sort();
  for (const id of sortedIds) {
    const bucket = buckets.get(id)!;
    const allPairings = [...bucket.pairings.values()];
    const sample_pairings = allPairings.slice(0, 5);
    patterns.push({
      pattern_id: bucket.meta.pattern_id,
      pattern_name: bucket.meta.pattern_name,
      pattern_summary: bucket.meta.pattern_summary,
      severity: bucket.meta.severity,
      paired_with_count: allPairings.length,
      sample_pairings,
    });
  }
  return patterns;
}

// ─── Kill-chain row → response shape ─────────────────────────────────────────

const CVE_PATTERN = /CVE-\d{4}-\d{4,7}/g;

/**
 * Extract CVE IDs cited in a chain narrative. The narrative is built by
 * `packages/attack-graph/src/narrative.ts` and includes a "Precedent: …"
 * paragraph that names CVEs verbatim (e.g. `CVE-2025-54135`).
 *
 * Returned IDs are deduplicated, uppercased, and stable-sorted so the
 * response is byte-stable across requests.
 */
function extractCveEvidenceIds(narrative: string): string[] {
  const seen = new Set<string>();
  const matches = narrative.match(CVE_PATTERN);
  if (!matches) return [];
  for (const m of matches) {
    seen.add(m.toUpperCase());
  }
  return [...seen].sort();
}

/**
 * Coerce the persisted `mitigations` array (typed as `unknown[]`) into a
 * flat `string[]` of human-readable mitigation descriptions. Each
 * mitigation row in `attack_chains` follows the
 * `packages/attack-graph` `Mitigation` shape: `{ description: string,
 * action: ..., target_server_id: ... }`. We extract `.description`
 * defensively — if the row is malformed we drop it rather than 500.
 */
function extractMitigationDescriptions(mitigations: unknown[]): string[] {
  const out: string[] = [];
  for (const m of mitigations) {
    if (m && typeof m === "object" && "description" in m) {
      const d = (m as { description: unknown }).description;
      if (typeof d === "string" && d.length > 0) {
        out.push(d);
      }
    }
  }
  return out;
}

export function buildKillChainsFromAttackChainRows(
  rows: PersistedAttackChainRow[],
): RiskBoundaryKillChain[] {
  const out: RiskBoundaryKillChain[] = [];
  for (const row of rows) {
    // exploitability_overall is `[0..1]` from the engine (see
    // packages/attack-graph/src/scoring.ts). The contract calls for a
    // [0..100] severity_score so the frontend can compare it directly
    // to the existing 0..100 score scale on the page. Round to 2 decimals
    // and clamp defensively in case a malformed row comes through.
    const raw = Number(row.exploitability_overall);
    const score = Number.isFinite(raw)
      ? Math.max(0, Math.min(100, Math.round(raw * 100)))
      : 0;
    out.push({
      kc_id: row.kill_chain_id,
      name: row.kill_chain_name,
      severity_score: score,
      narrative: row.narrative,
      // contributing_rule_ids: persisted attack_chains rows do not yet
      // carry the per-step rule_id link. The in-memory `AttackChain`
      // type has a `evidence.supporting_findings: string[]` field, but
      // it isn't persisted on the DB row. Returns an empty array — the
      // contract permits this and the frontend treats `[]` as "no rule
      // attribution on file". Wire-up tracked as a follow-up once
      // `evidence.supporting_findings` lands on the persisted row.
      contributing_rule_ids: [],
      cve_evidence_ids: extractCveEvidenceIds(row.narrative),
      mitigations: extractMitigationDescriptions(row.mitigations),
    });
  }
  return out;
}

// ─── Top-level assembly ─────────────────────────────────────────────────────

export interface BuildRiskBoundaryInput {
  server: Pick<Server, "id" | "slug" | "name">;
  riskEdges: PersistedRiskEdgeRow[];
  attackChains: PersistedAttackChainRow[];
}

/**
 * Assemble the full `RiskBoundaryResponse` for one server. Pure — no IO,
 * no DB, no fs. Caller (the route handler) does the DB work and passes
 * already-fetched rows in.
 */
export function buildRiskBoundary(
  input: BuildRiskBoundaryInput,
): RiskBoundaryResponse {
  return {
    server_slug: input.server.slug,
    server_name: input.server.name,
    same_config_patterns: buildPatternsFromRiskEdges(input.server.id, input.riskEdges),
    kill_chains: buildKillChainsFromAttackChainRows(input.attackChains),
  };
}
