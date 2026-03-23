export { AnalysisEngine, type AnalysisContext } from "./engine.js";
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

// Analysis toolkits (available for use by other packages)
export { shannonEntropy, classifyContent, slidingWindowEntropy } from "./rules/analyzers/entropy.js";
export { analyzeUnicode, normalizeConfusables } from "./rules/analyzers/unicode.js";
export { computeSimilarity, jaroWinkler, damerauLevenshtein } from "./rules/analyzers/similarity.js";
export { analyzeTaint, getUnsanitizedFlows } from "./rules/analyzers/taint.js";
export { buildCapabilityGraph } from "./rules/analyzers/capability-graph.js";
