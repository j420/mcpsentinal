/**
 * Exploitability Scoring — 7-Factor Weighted Model
 *
 * Computes a transparent, auditable exploitability score for each
 * attack chain. Every factor is independently testable with known
 * inputs and outputs.
 *
 * Factor weights sum to 1.0. The overall score is a weighted sum
 * (not noisy-OR — factors are correlated risk indicators, not
 * independent probabilities).
 *
 * Rating thresholds:
 *   >= 0.75 → critical
 *   >= 0.55 → high
 *   >= 0.35 → medium
 *   <  0.35 → low
 */
import type {
  AttackStep,
  ExploitabilityScore,
  ExploitabilityFactor,
  KillChainTemplate,
  CapabilityNode,
  RiskEdge,
} from "./types.js";

// ── Factor weights ─────────────────────────────────────────────────────────────
// Sum = 1.0

const WEIGHTS = {
  hop_count: 0.15,
  capability_confidence: 0.20,
  server_score_weakness: 0.15,
  real_world_precedent: 0.15,
  injection_gateway_present: 0.10,
  supporting_findings: 0.10,
  edge_severity: 0.15,
} as const;

// ── Rating thresholds ──────────────────────────────────────────────────────────

export function scoreToRating(score: number): ExploitabilityScore["rating"] {
  if (score >= 0.75) return "critical";
  if (score >= 0.55) return "high";
  if (score >= 0.35) return "medium";
  return "low";
}

// ── Individual factor computations ─────────────────────────────────────────────

/**
 * Factor 1: Hop Count
 *
 * Fewer hops = easier to exploit. A 2-hop chain (A→B) is more likely
 * to succeed than a 4-hop chain (A→B→C→D) because each hop is an
 * opportunity for the attack to fail.
 *
 * 2 hops → 1.0, 3 hops → 0.8, 4+ hops → 0.6
 */
export function computeHopCount(steps: AttackStep[]): ExploitabilityFactor {
  const hops = steps.length;
  let value: number;
  if (hops <= 2) value = 1.0;
  else if (hops === 3) value = 0.8;
  else value = 0.6;

  return {
    factor: "hop_count",
    value,
    weight: WEIGHTS.hop_count,
    description: `${hops} hop(s) in chain — ${hops <= 2 ? "short chain, high exploitability" : hops === 3 ? "moderate chain length" : "long chain, lower success probability"}`,
  };
}

/**
 * Factor 2: Capability Confidence
 *
 * How confidently we classified each server's capabilities. Computed
 * from the number of matching capabilities per server (more matches =
 * higher confidence that the server truly has the capability).
 *
 * Uses a heuristic: servers with 3+ capabilities matching their role
 * get 1.0 confidence, 2 gets 0.8, 1 gets 0.6. Averaged across steps.
 * Fallback: 0.7 if no capability data available.
 */
export function computeCapabilityConfidence(
  steps: AttackStep[]
): ExploitabilityFactor {
  if (steps.length === 0) {
    return {
      factor: "capability_confidence",
      value: 0.7,
      weight: WEIGHTS.capability_confidence,
      description: "No steps — default confidence 0.7",
    };
  }

  const confidences = steps.map((step) => {
    const capCount = step.capabilities_used.length;
    if (capCount >= 3) return 1.0;
    if (capCount >= 2) return 0.8;
    return 0.6;
  });

  const avg = confidences.reduce((sum, c) => sum + c, 0) / confidences.length;
  const value = Math.round(avg * 100) / 100; // 2 decimal precision

  return {
    factor: "capability_confidence",
    value,
    weight: WEIGHTS.capability_confidence,
    description: `Average capability confidence ${value.toFixed(2)} across ${steps.length} step(s)`,
  };
}

/**
 * Factor 3: Server Score Weakness
 *
 * The weakest server in the chain determines exploitability — attackers
 * target the weakest link. Lower scores = more vulnerabilities = easier
 * to exploit.
 *
 * Score < 40 → 1.0 (critical — many vulnerabilities)
 * Score 40-59 → 0.8 (poor)
 * Score 60-79 → 0.5 (moderate)
 * Score >= 80 → 0.2 (good — harder to exploit)
 * Score null → 0.7 (unknown — conservative assumption)
 */
export function computeServerScoreWeakness(
  nodes: CapabilityNode[]
): ExploitabilityFactor {
  if (nodes.length === 0) {
    return {
      factor: "server_score_weakness",
      value: 0.7,
      weight: WEIGHTS.server_score_weakness,
      description: "No servers — default weakness 0.7",
    };
  }

  const scores = nodes.map((n) => n.latest_score);
  const minScore = scores.reduce<number | null>((min, s) => {
    if (s === null) return min;
    if (min === null) return s;
    return Math.min(min, s);
  }, null);

  let value: number;
  let desc: string;

  if (minScore === null) {
    value = 0.7;
    desc = "All servers unscored — conservative assumption (0.7)";
  } else if (minScore < 40) {
    value = 1.0;
    desc = `Weakest server score ${minScore} (critical) — highly exploitable`;
  } else if (minScore < 60) {
    value = 0.8;
    desc = `Weakest server score ${minScore} (poor) — many vulnerabilities`;
  } else if (minScore < 80) {
    value = 0.5;
    desc = `Weakest server score ${minScore} (moderate) — some defenses present`;
  } else {
    value = 0.2;
    desc = `Weakest server score ${minScore} (good) — harder to exploit`;
  }

  return {
    factor: "server_score_weakness",
    value,
    weight: WEIGHTS.server_score_weakness,
    description: desc,
  };
}

/**
 * Factor 4: Real-World Precedent
 *
 * Templates with documented real-world attacks or CVEs get higher scores
 * because the attack has been proven feasible in practice.
 *
 * Has CVE/incident precedent → 1.0
 * Has research paper precedent → 0.8
 * No precedent → 0.5
 */
export function computeRealWorldPrecedent(
  template: KillChainTemplate
): ExploitabilityFactor {
  const hasPrecedent = template.precedent.length > 0;
  const hasCVE = /CVE-\d{4}-\d+/i.test(template.precedent);

  let value: number;
  let desc: string;

  if (hasCVE) {
    value = 1.0;
    desc = `CVE-backed precedent: ${template.precedent.slice(0, 80)}...`;
  } else if (hasPrecedent) {
    value = 0.8;
    desc = `Research-backed precedent: ${template.precedent.slice(0, 80)}...`;
  } else {
    value = 0.5;
    desc = "No documented real-world precedent";
  }

  return {
    factor: "real_world_precedent",
    value,
    weight: WEIGHTS.real_world_precedent,
    description: desc,
  };
}

/**
 * Factor 5: Injection Gateway Present
 *
 * Chains that start with a confirmed injection gateway (web scraper,
 * email reader, etc.) are significantly more likely to be exploited
 * because the attacker has a clear entry point.
 *
 * Chain starts with injection_gateway role + node.is_injection_gateway → 1.0
 * Chain has injection_gateway role but node not confirmed → 0.6
 * No injection gateway in chain → 0.3
 */
export function computeInjectionGatewayPresent(
  steps: AttackStep[],
  nodes: CapabilityNode[]
): ExploitabilityFactor {
  const gatewayStep = steps.find((s) => s.role === "injection_gateway");

  if (!gatewayStep) {
    return {
      factor: "injection_gateway_present",
      value: 0.3,
      weight: WEIGHTS.injection_gateway_present,
      description: "No injection gateway in chain — attacker needs alternative entry",
    };
  }

  const gatewayNode = nodes.find((n) => n.server_id === gatewayStep.server_id);
  if (gatewayNode?.is_injection_gateway) {
    return {
      factor: "injection_gateway_present",
      value: 1.0,
      weight: WEIGHTS.injection_gateway_present,
      description: `Confirmed injection gateway: ${gatewayNode.server_name}`,
    };
  }

  return {
    factor: "injection_gateway_present",
    value: 0.6,
    weight: WEIGHTS.injection_gateway_present,
    description: `Injection gateway role filled by ${gatewayStep.server_name} but not confirmed as gateway`,
  };
}

/**
 * Factor 6: Supporting Findings
 *
 * Boost if participating servers have relevant single-server findings
 * (e.g., F1 lethal trifecta, G1 injection gateway, C1 command injection).
 * More supporting findings = stronger evidence the chain is viable.
 *
 * 3+ supporting findings → 1.0
 * 1-2 supporting findings → 0.7
 * 0 supporting findings → 0.3
 */
export function computeSupportingFindings(
  serverFindings: Record<string, string[]> | undefined,
  participatingServerIds: string[]
): ExploitabilityFactor {
  if (!serverFindings) {
    return {
      factor: "supporting_findings",
      value: 0.3,
      weight: WEIGHTS.supporting_findings,
      description: "No single-server finding data available",
    };
  }

  const relevantFindings = participatingServerIds.flatMap(
    (id) => serverFindings[id] ?? []
  );
  const count = relevantFindings.length;

  let value: number;
  if (count >= 3) value = 1.0;
  else if (count >= 1) value = 0.7;
  else value = 0.3;

  return {
    factor: "supporting_findings",
    value,
    weight: WEIGHTS.supporting_findings,
    description:
      count > 0
        ? `${count} supporting finding(s) on participating servers: ${relevantFindings.slice(0, 5).join(", ")}`
        : "No supporting findings on participating servers",
  };
}

/**
 * Factor 7: Edge Severity
 *
 * Average severity of the risk-matrix edges connecting chain steps.
 * Higher severity edges = more dangerous connections.
 *
 * critical → 1.0, high → 0.75, medium → 0.5, low → 0.25
 */
export function computeEdgeSeverity(
  edges: RiskEdge[]
): ExploitabilityFactor {
  if (edges.length === 0) {
    return {
      factor: "edge_severity",
      value: 0.5,
      weight: WEIGHTS.edge_severity,
      description: "No edges — default severity 0.5",
    };
  }

  const severityValues: Record<string, number> = {
    critical: 1.0,
    high: 0.75,
    medium: 0.5,
    low: 0.25,
  };

  const avg =
    edges.reduce((sum, e) => sum + (severityValues[e.severity] ?? 0.5), 0) /
    edges.length;

  const value = Math.round(avg * 100) / 100;

  return {
    factor: "edge_severity",
    value,
    weight: WEIGHTS.edge_severity,
    description: `Average edge severity ${value.toFixed(2)} across ${edges.length} edge(s)`,
  };
}

// ── Composite scoring ──────────────────────────────────────────────────────────

export interface ScoringInput {
  steps: AttackStep[];
  template: KillChainTemplate;
  nodes: CapabilityNode[];
  edges: RiskEdge[];
  serverFindings?: Record<string, string[]>;
}

/**
 * Compute the full exploitability score for an attack chain.
 *
 * Returns a transparent, auditable score with all 7 factors visible.
 * The overall score is clamped to [0.0, 1.0].
 */
export function computeExploitability(input: ScoringInput): ExploitabilityScore {
  const participatingIds = input.steps.map((s) => s.server_id);
  const participatingNodes = input.nodes.filter((n) =>
    participatingIds.includes(n.server_id)
  );

  // Compute all 7 factors
  const factors: ExploitabilityFactor[] = [
    computeHopCount(input.steps),
    computeCapabilityConfidence(input.steps),
    computeServerScoreWeakness(participatingNodes),
    computeRealWorldPrecedent(input.template),
    computeInjectionGatewayPresent(input.steps, input.nodes),
    computeSupportingFindings(input.serverFindings, participatingIds),
    computeEdgeSeverity(input.edges),
  ];

  // Weighted sum
  const overall = Math.min(
    1.0,
    Math.max(
      0.0,
      factors.reduce((sum, f) => sum + f.value * f.weight, 0)
    )
  );

  // Round to 3 decimal places for determinism
  const rounded = Math.round(overall * 1000) / 1000;

  // Derive likelihood, impact, effort from base template values + factor adjustments
  const likelihood = Math.min(
    1.0,
    input.template.base_likelihood *
      (factors[0].value * 0.4 + factors[4].value * 0.3 + factors[3].value * 0.3)
  );
  const impact = Math.min(
    1.0,
    input.template.base_impact *
      (factors[2].value * 0.4 + factors[6].value * 0.3 + factors[5].value * 0.3)
  );
  const effort = factors[0].value * 0.5 + factors[1].value * 0.5;

  return {
    overall: rounded,
    likelihood: Math.round(likelihood * 1000) / 1000,
    impact: Math.round(impact * 1000) / 1000,
    effort: Math.round(effort * 1000) / 1000,
    rating: scoreToRating(rounded),
    factors,
  };
}
