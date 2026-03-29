/**
 * Attack Graph Engine — Multi-Step Kill Chain Synthesis
 *
 * Synthesizes individual risk-matrix edges (P01-P12) into ordered attack
 * chains with exploitability scoring, human-readable narratives, and
 * actionable mitigations.
 *
 * Usage:
 *   const engine = new AttackGraphEngine();
 *   const report = engine.analyze({
 *     nodes: buildCapabilityGraph(servers),
 *     edges: riskReport.edges,
 *     patternsDetected: riskReport.patterns_detected,
 *   });
 */

export { AttackGraphEngine } from "./engine.js";
export { ALL_KILL_CHAINS, hasRequiredPatterns, hasRequiredEdgeTypes } from "./kill-chains.js";
export {
  computeExploitability,
  computeHopCount,
  computeCapabilityConfidence,
  computeServerScoreWeakness,
  computeRealWorldPrecedent,
  computeInjectionGatewayPresent,
  computeSupportingFindings,
  computeEdgeSeverity,
  scoreToRating,
} from "./scoring.js";
export { generateNarrative, generateMitigations } from "./narrative.js";
export type {
  AttackGraphInput,
  AttackGraphReport,
  AttackChain,
  AttackStep,
  AttackRole,
  AttackObjective,
  ExploitabilityScore,
  ExploitabilityFactor,
  Mitigation,
  ChainEvidence,
  KillChainTemplate,
  KillChainRole,
} from "./types.js";
