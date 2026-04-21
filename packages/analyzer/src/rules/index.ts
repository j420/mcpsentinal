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
import "./implementations/c1-command-injection/index.js";
import "./implementations/c4-sql-injection/index.js";
import "./implementations/c12-unsafe-deserialization/index.js";
import "./implementations/c13-ssti/index.js";
import "./implementations/c16-eval-injection/index.js";
import "./implementations/k9-dangerous-post-install-hooks/index.js";
import "./implementations/j2-git-argument-injection/index.js";
import "./implementations/a6-unicode-homoglyph/index.js";
import "./implementations/a7-zero-width-injection/index.js";
import "./implementations/a9-encoded-instructions/index.js";
import "./implementations/d3-typosquatting/index.js";
import "./implementations/f1-lethal-trifecta.js";
import "./implementations/g4-context-saturation.js";
// tainted-execution-detector.ts removed in Phase 1 Chunk 1.16; its six rules
// (C4, C12, C13, C16, K9, J2) have each been migrated to their own directory.
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
import "./implementations/k1-absent-structured-logging/index.js";
import "./implementations/k4-missing-human-confirmation/index.js";
import "./implementations/k6-overly-broad-oauth-scopes/index.js";
import "./implementations/k7-long-lived-tokens/index.js";
import "./implementations/k17-missing-timeout/index.js";
import "./implementations/k-remaining-v2.js";
import "./implementations/m4-tool-squatting.js";
import "./implementations/m5-context-window-flooding.js";
import "./implementations/l-supply-chain-v2.js";
import "./implementations/o4-q10-v2.js";
import "./implementations/docker-k8s-crypto-v2.js";
import "./implementations/jsonrpc-protocol-v2.js";
import "./implementations/k-compliance-v2.js";
import "./implementations/k12-executable-content-response/index.js";
import "./implementations/k14-agent-credential-propagation/index.js";
import "./implementations/k16-unbounded-recursion/index.js";
import "./implementations/k20-insufficient-audit-context/index.js";
import "./implementations/m-runtime-v2.js";
import "./implementations/compliance-remaining-detector.js";
