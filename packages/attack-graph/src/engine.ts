/**
 * Attack Graph Engine — Template-Driven Chain Synthesis
 *
 * Algorithm:
 *   For each KillChainTemplate:
 *     1. PREREQUISITE CHECK: required patterns ∩ detected patterns ≠ ∅?
 *        Required edge types all present?
 *     2. ROLE ASSIGNMENT: For each role, find candidate servers matching
 *        capabilities + flags
 *     3. COMBINATION GENERATION: Cartesian product with distinct-server
 *        constraint (unless template allows overlap)
 *     4. EDGE VERIFICATION: Risk-matrix edges must connect consecutive
 *        role-servers
 *     5. SCORE: computeExploitability() for each valid chain
 *     6. DEDUPLICATE: same server set + template → keep highest score
 *     7. NARRATE: generateNarrative() + generateMitigations()
 *
 * Complexity: O(T × N^R) where T=templates, N=servers, R=max roles.
 * Practical: 3-10 server configs produce 0-20 chains.
 * Safety cap: 100 chains max across all templates.
 */
import { createHash } from "crypto";
import { ALL_KILL_CHAINS, hasRequiredPatterns, hasRequiredEdgeTypes } from "./kill-chains.js";
import { computeExploitability } from "./scoring.js";
import { generateNarrative, generateMitigations } from "./narrative.js";
import type {
  AttackGraphInput,
  AttackGraphReport,
  AttackChain,
  AttackStep,
  AttackRole,
  CapabilityNode,
  Capability,
  RiskEdge,
  KillChainTemplate,
  KillChainRole,
  ChainEvidence,
} from "./types.js";

/** Maximum chains across ALL templates (safety valve) */
const MAX_CHAINS = 100;

/** Maximum combinations to evaluate per template (prevents combinatorial explosion) */
const MAX_COMBINATIONS_PER_TEMPLATE = 500;

// ── Main engine ────────────────────────────────────────────────────────────────

export class AttackGraphEngine {
  /**
   * Analyze a server configuration for multi-step attack chains.
   *
   * @param input — Capability nodes, risk-matrix edges, and detected patterns
   * @returns AttackGraphReport with synthesized chains ordered by exploitability
   */
  analyze(input: AttackGraphInput): AttackGraphReport {
    const { nodes, edges, patterns_detected, server_findings } = input;

    const configId = createHash("sha256")
      .update(nodes.map((n) => n.server_id).sort().join(","))
      .digest("hex")
      .slice(0, 16);

    const allChains: AttackChain[] = [];

    for (const template of ALL_KILL_CHAINS) {
      if (allChains.length >= MAX_CHAINS) break;

      // Step 1: Prerequisite check
      if (!hasRequiredPatterns(template, patterns_detected)) continue;
      if (!hasRequiredEdgeTypes(template, edges)) continue;

      // Step 2: Role assignment — find candidates per role
      const candidatesPerRole = template.roles.map((role) =>
        findCandidates(role, nodes)
      );

      // Prune: if any role has zero candidates, skip template
      if (candidatesPerRole.some((c) => c.length === 0)) continue;

      // Step 3: Generate combinations (distinct servers per role)
      const combinations = generateCombinations(
        candidatesPerRole,
        template.min_servers
      );

      // Step 4-7: Verify, score, deduplicate, narrate
      for (const combo of combinations) {
        if (allChains.length >= MAX_CHAINS) break;

        // Step 4: Edge verification
        const chainEdges = verifyEdges(combo, template, edges);
        if (chainEdges === null) continue;

        // Build steps
        const steps = buildSteps(combo, template, chainEdges);

        // Step 5: Score
        const exploitability = computeExploitability({
          steps,
          template,
          nodes,
          edges: chainEdges,
          serverFindings: server_findings,
        });

        // Build evidence
        const evidence: ChainEvidence = {
          risk_edges: chainEdges,
          pattern_ids: template.required_patterns.filter((p) =>
            patterns_detected.includes(p)
          ),
          supporting_findings: getRelevantFindings(
            steps.map((s) => s.server_id),
            server_findings
          ),
        };

        // Step 7: Narrate
        const narrative = generateNarrative(template, steps);
        const mitigations = generateMitigations(template, steps, nodes);

        // Generate deterministic chain ID
        const chainId = createHash("sha256")
          .update(
            steps.map((s) => s.server_id).sort().join(",") + ":" + template.id
          )
          .digest("hex")
          .slice(0, 16);

        allChains.push({
          chain_id: chainId,
          kill_chain_id: template.id,
          kill_chain_name: template.name,
          steps,
          exploitability,
          narrative,
          mitigations,
          owasp_refs: template.owasp,
          mitre_refs: template.mitre,
          evidence,
        });
      }
    }

    // Step 6: Deduplicate (same server set + template → keep highest score)
    const deduped = deduplicateChains(allChains);

    // Sort by exploitability descending
    deduped.sort((a, b) => b.exploitability.overall - a.exploitability.overall);

    // Aggregate risk
    const aggregateRisk = computeAggregateRisk(deduped);

    return {
      generated_at: new Date().toISOString(),
      config_id: configId,
      server_count: nodes.length,
      chains: deduped,
      chain_count: deduped.length,
      critical_chains: deduped.filter((c) => c.exploitability.rating === "critical").length,
      high_chains: deduped.filter((c) => c.exploitability.rating === "high").length,
      aggregate_risk: aggregateRisk,
      summary: buildSummary(deduped, nodes.length, aggregateRisk),
    };
  }
}

// ── Role matching ──────────────────────────────────────────────────────────────

/**
 * Find servers that can fill a specific role.
 *
 * A server matches if:
 *   1. It satisfies ANY capability group (OR) — where each group requires
 *      ALL capabilities in that group (AND)
 *   2. It satisfies any flag requirements (is_injection_gateway, is_shared_writer)
 */
export function findCandidates(
  role: KillChainRole,
  nodes: CapabilityNode[]
): CapabilityNode[] {
  return nodes.filter((node) => {
    // Check capability requirements (OR of AND groups)
    const capMatch = role.required_capabilities.some((group) =>
      group.every((cap) => node.capabilities.includes(cap))
    );
    if (!capMatch) return false;

    // Check flags
    if (role.flags?.is_injection_gateway && !node.is_injection_gateway) return false;
    if (role.flags?.is_shared_writer && !node.is_shared_writer) return false;

    return true;
  });
}

// ── Combination generation ─────────────────────────────────────────────────────

/**
 * Generate all valid combinations of candidates across roles.
 *
 * Constraints:
 *   - Each server appears at most once per combination (distinct-server)
 *   - Total distinct servers >= template.min_servers
 *   - Capped at MAX_COMBINATIONS_PER_TEMPLATE to prevent explosion
 */
export function generateCombinations(
  candidatesPerRole: CapabilityNode[][],
  minServers: number
): CapabilityNode[][] {
  const results: CapabilityNode[][] = [];

  function recurse(roleIdx: number, current: CapabilityNode[], usedIds: Set<string>): void {
    if (results.length >= MAX_COMBINATIONS_PER_TEMPLATE) return;

    if (roleIdx === candidatesPerRole.length) {
      // Check min_servers constraint
      const distinctIds = new Set(current.map((n) => n.server_id));
      if (distinctIds.size >= minServers) {
        results.push([...current]);
      }
      return;
    }

    for (const candidate of candidatesPerRole[roleIdx]) {
      if (usedIds.has(candidate.server_id)) continue;
      current.push(candidate);
      usedIds.add(candidate.server_id);
      recurse(roleIdx + 1, current, usedIds);
      current.pop();
      usedIds.delete(candidate.server_id);
    }
  }

  recurse(0, [], new Set());
  return results;
}

// ── Edge verification ──────────────────────────────────────────────────────────

/**
 * Verify that risk-matrix edges connect consecutive role-servers.
 *
 * For a chain [A, B, C], we need edges A→B and B→C (or B→A, C→B — direction
 * depends on edge type semantics, so we check both directions).
 *
 * Returns the matching edges, or null if the chain is not fully connected.
 */
export function verifyEdges(
  combo: CapabilityNode[],
  template: KillChainTemplate,
  allEdges: RiskEdge[]
): RiskEdge[] | null {
  if (combo.length < 2) return null;

  const chainEdges: RiskEdge[] = [];

  for (let i = 0; i < combo.length - 1; i++) {
    const fromId = combo[i].server_id;
    const toId = combo[i + 1].server_id;

    // Find an edge connecting these two servers (either direction)
    const edge = allEdges.find(
      (e) =>
        (e.from_server_id === fromId && e.to_server_id === toId) ||
        (e.from_server_id === toId && e.to_server_id === fromId)
    );

    if (!edge) return null; // Chain broken — no edge between consecutive servers
    chainEdges.push(edge);
  }

  return chainEdges;
}

// ── Step building ──────────────────────────────────────────────────────────────

function buildSteps(
  combo: CapabilityNode[],
  template: KillChainTemplate,
  chainEdges: RiskEdge[]
): AttackStep[] {
  return combo.map((node, idx) => {
    const role = template.roles[idx];
    // Find which capabilities from the role requirements this server has
    const capsUsed = findMatchingCapabilities(role, node);

    return {
      ordinal: idx + 1,
      server_id: node.server_id,
      server_name: node.server_name,
      role: role.role,
      capabilities_used: capsUsed,
      tools_involved: [], // populated later if tool-level data available
      edge_to_next: idx < chainEdges.length ? chainEdges[idx] : null,
      narrative: "", // populated by generateNarrative
    };
  });
}

function findMatchingCapabilities(
  role: KillChainRole,
  node: CapabilityNode
): Capability[] {
  // Find the first matching capability group
  for (const group of role.required_capabilities) {
    if (group.every((cap) => node.capabilities.includes(cap))) {
      return group;
    }
  }
  // Fallback: return all node capabilities that appear in any group
  const allRoleCaps = new Set(role.required_capabilities.flat());
  return node.capabilities.filter((cap) => allRoleCaps.has(cap));
}

// ── Deduplication ──────────────────────────────────────────────────────────────

function deduplicateChains(chains: AttackChain[]): AttackChain[] {
  const best = new Map<string, AttackChain>();

  for (const chain of chains) {
    const key = chain.chain_id; // Already a hash of sorted server_ids + template
    const existing = best.get(key);
    if (!existing || chain.exploitability.overall > existing.exploitability.overall) {
      best.set(key, chain);
    }
  }

  return Array.from(best.values());
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function getRelevantFindings(
  serverIds: string[],
  serverFindings?: Record<string, string[]>
): string[] {
  if (!serverFindings) return [];
  return serverIds.flatMap((id) => serverFindings[id] ?? []);
}

function computeAggregateRisk(
  chains: AttackChain[]
): AttackGraphReport["aggregate_risk"] {
  if (chains.length === 0) return "none";
  if (chains.some((c) => c.exploitability.rating === "critical")) return "critical";
  if (chains.some((c) => c.exploitability.rating === "high")) return "high";
  if (chains.some((c) => c.exploitability.rating === "medium")) return "medium";
  return "low";
}

function buildSummary(
  chains: AttackChain[],
  serverCount: number,
  risk: AttackGraphReport["aggregate_risk"]
): string {
  if (chains.length === 0) {
    return `${serverCount} server(s) analysed. No multi-step attack chains detected.`;
  }

  const critical = chains.filter((c) => c.exploitability.rating === "critical").length;
  const high = chains.filter((c) => c.exploitability.rating === "high").length;

  const parts = [
    `${serverCount} server(s) in config. Aggregate chain risk: ${risk.toUpperCase()}.`,
    `${chains.length} attack chain(s) detected.`,
  ];

  if (critical > 0) {
    parts.push(`${critical} CRITICAL chain(s).`);
  }
  if (high > 0) {
    parts.push(`${high} HIGH chain(s).`);
  }

  return parts.join(" ");
}
