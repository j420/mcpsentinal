/**
 * Risk Matrix Analyzer — cross-server capability graph and attack path detection.
 *
 * Usage:
 *   const analyzer = new RiskMatrixAnalyzer();
 *   const report = analyzer.analyze(servers);
 *
 * The report surfaces dangerous capability combinations across the server set:
 *   - Cross-config lethal trifecta (extends F1 to multi-server)
 *   - Credential harvesting chains
 *   - Injection propagation paths (web scraper → code executor)
 *   - Shared memory pollution (vector store poisoning)
 *   - Agent config poisoning
 *   - And 7 more patterns (P01-P12)
 */
import { createHash } from "crypto";
import { buildCapabilityGraph } from "./graph.js";
import { ALL_PATTERNS } from "./patterns.js";
import type { RiskEdge, RiskMatrixReport, CapabilityNode } from "./types.js";

export { buildCapabilityGraph, buildCapabilityNode } from "./graph.js";
export { ALL_PATTERNS } from "./patterns.js";
export type {
  CapabilityNode,
  RiskEdge,
  RiskPattern,
  RiskMatrixReport,
  Capability,
  EdgeType,
} from "./types.js";

// ── Severity ordering ─────────────────────────────────────────────────────────

const SEVERITY_ORDER = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
type AggSeverity = keyof typeof SEVERITY_ORDER;

function maxSeverity(edges: RiskEdge[]): AggSeverity {
  if (edges.length === 0) return "none";
  let max: AggSeverity = "low";
  for (const e of edges) {
    if (SEVERITY_ORDER[e.severity] > SEVERITY_ORDER[max]) {
      max = e.severity;
    }
  }
  return max;
}

// ── Score caps from critical patterns ─────────────────────────────────────────

/**
 * If a cross-config lethal trifecta (P01) or multi-hop exfiltration (P12)
 * is detected, cap all participating servers at 40 (same as F1).
 */
function computeScoreCaps(
  nodes: CapabilityNode[],
  edges: RiskEdge[]
): Record<string, number> {
  const caps: Record<string, number> = {};

  const criticalEdges = edges.filter((e) => e.severity === "critical");
  if (criticalEdges.length > 0) {
    const affectedIds = new Set<string>();
    for (const e of criticalEdges) {
      affectedIds.add(e.from_server_id);
      affectedIds.add(e.to_server_id);
    }
    for (const id of affectedIds) {
      const node = nodes.find((n) => n.server_id === id);
      if (node && (node.latest_score === null || node.latest_score > 40)) {
        caps[id] = 40;
      }
    }
  }

  return caps;
}

// ── Main analyzer ─────────────────────────────────────────────────────────────

export class RiskMatrixAnalyzer {
  /**
   * Analyze a set of servers from a single MCP client config.
   *
   * @param servers - Servers with their tools and capability_tags
   */
  analyze(
    servers: Parameters<typeof buildCapabilityGraph>[0]
  ): RiskMatrixReport {
    const nodes = buildCapabilityGraph(servers);
    const configId = createHash("sha256")
      .update(servers.map((s) => s.server_id).sort().join(","))
      .digest("hex")
      .slice(0, 16);

    const allEdges: RiskEdge[] = [];
    const firedPatternIds: string[] = [];

    for (const pattern of ALL_PATTERNS) {
      const patternEdges = pattern.detect(nodes);
      if (patternEdges.length > 0) {
        // Stamp pattern_id onto every edge so consumers can group/filter by pattern
        allEdges.push(...patternEdges.map((e) => ({ ...e, pattern_id: pattern.id })));
        firedPatternIds.push(pattern.id);
      }
    }

    // Deduplicate edges (same from/to/type)
    const uniqueEdges = deduplicate(allEdges);

    const aggregateRisk = maxSeverity(uniqueEdges);
    const scoreCaps = computeScoreCaps(nodes, uniqueEdges);

    const summary = buildSummary(nodes, uniqueEdges, firedPatternIds, aggregateRisk);

    return {
      generated_at: new Date().toISOString(),
      config_id: configId,
      server_count: servers.length,
      edges: uniqueEdges,
      patterns_detected: firedPatternIds,
      aggregate_risk: aggregateRisk,
      score_caps: scoreCaps,
      summary,
    };
  }
}

function deduplicate(edges: RiskEdge[]): RiskEdge[] {
  const seen = new Set<string>();
  return edges.filter((e) => {
    const key = `${e.from_server_id}:${e.to_server_id}:${e.edge_type}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function buildSummary(
  nodes: CapabilityNode[],
  edges: RiskEdge[],
  patterns: string[],
  risk: AggSeverity
): string {
  if (edges.length === 0) {
    return `${nodes.length} server(s) analysed. No dangerous cross-server capability combinations detected.`;
  }

  const criticalEdges = edges.filter((e) => e.severity === "critical");
  const highEdges = edges.filter((e) => e.severity === "high");

  const parts = [
    `${nodes.length} server(s) in config. Aggregate risk: ${risk.toUpperCase()}.`,
    `${edges.length} attack edge(s) detected across ${patterns.length} pattern(s).`,
  ];

  if (criticalEdges.length > 0) {
    parts.push(`${criticalEdges.length} CRITICAL edge(s): ${criticalEdges.map((e) => e.edge_type).join(", ")}.`);
  }
  if (highEdges.length > 0) {
    parts.push(`${highEdges.length} HIGH edge(s).`);
  }

  return parts.join(" ");
}
