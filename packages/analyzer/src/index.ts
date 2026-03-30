export { AnalysisEngine, type AnalysisContext, type ProfiledAnalysisResult } from "./engine.js";
export { loadRules, getRulesVersion } from "./rule-loader.js";
export {
  fingerprintTool,
  pinServerTools,
  diffToolPins,
  type ToolFingerprint,
  type ServerToolPin,
  type ToolPinDiff,
} from "./tool-fingerprint.js";

// Typed rules — import to auto-register all TypeScript rule implementations.
// These replace YAML regex rules with real analysis: taint tracking, entropy,
// graph algorithms, Unicode codepoint analysis, multi-algorithm similarity.
export {
  type TypedRule,
  type TypedFinding,
  getAllTypedRules,
  hasTypedRule,
} from "./rules/index.js";

// Phase 1 rebuild: Profile-aware analysis
export {
  profileServer,
  type ServerProfile,
  type ServerCapability,
  type InferredCapability,
  type AttackSurface,
  type DataFlowPair,
} from "./profiler.js";

export {
  EvidenceChainBuilder,
  renderEvidenceNarrative,
  type EvidenceChain,
  type EvidenceLink,
  type SourceLink,
  type PropagationLink,
  type SinkLink,
  type MitigationLink,
  type ImpactLink,
  type ThreatReference,
  type VerificationStep,
} from "./evidence.js";

export {
  THREAT_REGISTRY,
  UNIVERSAL_EVIDENCE_STANDARD,
  selectThreats,
  getRelevantRuleIds,
  getEvidenceStandard,
  type ThreatDefinition,
  type EvidenceStandard,
} from "./threat-model.js";

export {
  EVIDENCE_CHAIN_GRACE_PERIOD,
  annotateFindings,
  scoredFindings,
  unscoredFindings,
  generateProfileReport,
  type AnnotatedFinding,
  type ScoredFinding,
} from "./relevance.js";

// Analysis toolkits (available for use by other packages)
export { shannonEntropy, classifyContent, slidingWindowEntropy } from "./rules/analyzers/entropy.js";
export { analyzeUnicode, normalizeConfusables } from "./rules/analyzers/unicode.js";
export { computeSimilarity, jaroWinkler, damerauLevenshtein } from "./rules/analyzers/similarity.js";
export { analyzeTaint, getUnsanitizedFlows } from "./rules/analyzers/taint.js";
export { analyzeASTTaint, getUnsanitizedASTFlows } from "./rules/analyzers/taint-ast.js";
export { buildCapabilityGraph } from "./rules/analyzers/capability-graph.js";
export { analyzeSchema, analyzeToolSet } from "./rules/analyzers/schema-inference.js";
