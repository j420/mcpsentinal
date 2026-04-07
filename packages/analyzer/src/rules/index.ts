/**
 * TypedRule Registry — Auto-registers all typed rule implementations.
 *
 * Import this module to register all typed rules with the engine.
 * Each implementation file calls registerTypedRule() on import.
 */

// Core framework — v1 (legacy, backward-compatible)
export {
  type TypedRule,
  type TypedFinding,
  registerTypedRule,
  getTypedRule,
  getAllTypedRules,
  hasTypedRule,
} from "./base.js";

// Core framework — v2 (mandatory evidence chains)
export {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
  getTypedRuleV2,
  getAllTypedRulesV2,
  hasNativeV2Rule,
  migrationStats,
  checkRequirements,
  ruleResultToTypedFinding,
  V1RuleAdapter,
} from "./base.js";

// Analyzers (shared analysis toolkits)
export * as entropy from "./analyzers/entropy.js";
export * as unicode from "./analyzers/unicode.js";
export * as similarity from "./analyzers/similarity.js";
export * as taint from "./analyzers/taint.js";
export * as taintAST from "./analyzers/taint-ast.js";
export * as capabilityGraph from "./analyzers/capability-graph.js";
export * as schemaInference from "./analyzers/schema-inference.js";

// Rule implementations (self-registering on import)
import "./implementations/c1-command-injection.js";
import "./implementations/a6-unicode-homoglyph.js";
import "./implementations/a9-encoded-instructions.js";
import "./implementations/d3-typosquatting.js";
import "./implementations/f1-lethal-trifecta.js";
import "./implementations/g4-context-saturation.js";
import "./implementations/tainted-execution-detector.js";
import "./implementations/cross-tool-risk-detector.js";
import "./implementations/config-poisoning-detector.js";
import "./implementations/secret-exfil-detector.js";
import "./implementations/supply-chain-detector.js";
import "./implementations/code-security-deep-detector.js";
import "./implementations/ai-manipulation-detector.js";
import "./implementations/infrastructure-detector.js";
import "./implementations/advanced-supply-chain-detector.js";
import "./implementations/protocol-ai-runtime-detector.js";
import "./implementations/data-privacy-cross-ecosystem-detector.js";
import "./implementations/description-schema-detector.js";
import "./implementations/code-remaining-detector.js";
import "./implementations/dependency-behavioral-detector.js";
import "./implementations/ecosystem-adversarial-detector.js";
import "./implementations/protocol-surface-remaining-detector.js";
import "./implementations/k1-absent-structured-logging.js";
import "./implementations/compliance-remaining-detector.js";
