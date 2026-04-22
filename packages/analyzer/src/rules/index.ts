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
// config-poisoning-detector.ts removed in Phase 1 Chunk 1.15; its four rules
// (J1, L4, L11, Q4) have each been migrated to their own directory.
import "./implementations/j1-cross-agent-config-poisoning/index.js";
import "./implementations/l4-mcp-config-code-injection/index.js";
import "./implementations/l11-env-var-injection-via-config/index.js";
import "./implementations/q4-ide-mcp-config-injection/index.js";
// secret-exfil-detector.ts removed in Phase 1 Chunk 1.14; its three rules
// (L9, K2, G7) have each been migrated to their own directory.
import "./implementations/l9-ci-secret-exfiltration/index.js";
import "./implementations/k2-audit-trail-destruction/index.js";
import "./implementations/g7-dns-exfiltration-channel/index.js";
import "./implementations/supply-chain-detector.js";
// code-security-deep-detector.ts removed in Phase 1 Chunk 1.18; its four rules
// (C2, C5, C10, C14) have each been migrated to their own directory.
import "./implementations/c2-path-traversal/index.js";
import "./implementations/c5-hardcoded-secrets/index.js";
import "./implementations/c10-prototype-pollution/index.js";
import "./implementations/c14-jwt-algorithm-confusion/index.js";
// Chunk 1.9: L1/L2/L6/L13 migrated out of advanced-supply-chain-detector.ts
// into per-rule Rule Standard v2 directories (L7/K3/K5/K8 remain in the legacy
// file as tombstones). These imports are appended after the C-rules to keep
// the taint-kit-based rules registered after their shared infrastructure.
import "./implementations/l1-github-actions-tag-poisoning/index.js";
import "./implementations/l2-malicious-build-plugin/index.js";
import "./implementations/l6-config-symlink-attack/index.js";
import "./implementations/l13-build-credential-file-theft/index.js";
import "./implementations/ai-manipulation-detector.js";
import "./implementations/infrastructure-detector.js";
import "./implementations/advanced-supply-chain-detector.js";
import "./implementations/protocol-ai-runtime-detector.js";
import "./implementations/data-privacy-cross-ecosystem-detector.js";
import "./implementations/description-schema-detector.js";
import "./implementations/dependency-behavioral-detector.js";
import "./implementations/ecosystem-adversarial-detector.js";
import "./implementations/protocol-surface-remaining-detector.js";
import "./implementations/k1-absent-structured-logging/index.js";
import "./implementations/k4-missing-human-confirmation/index.js";
import "./implementations/k6-overly-broad-oauth-scopes/index.js";
import "./implementations/k7-long-lived-tokens/index.js";
import "./implementations/k17-missing-timeout/index.js";
import "./implementations/m4-tool-squatting.js";
import "./implementations/m5-context-window-flooding.js";
import "./implementations/l-supply-chain-v2.js";
import "./implementations/o4-q10-v2.js";
import "./implementations/docker-k8s-crypto-v2.js";
// Phase 1 chunk 1.8: N1-N3, N7, N8, N10 migrated out of jsonrpc-protocol-v2.ts
// into per-rule Rule Standard v2 directories. The legacy file is deleted.
import "./implementations/n1-jsonrpc-batch-request-abuse/index.js";
import "./implementations/n2-jsonrpc-notification-flooding/index.js";
import "./implementations/n3-jsonrpc-id-collision/index.js";
import "./implementations/n7-progress-token-abuse/index.js";
import "./implementations/n8-cancellation-race-condition/index.js";
import "./implementations/n10-incomplete-handshake-dos/index.js";
import "./implementations/k-compliance-v2.js";
import "./implementations/k11-missing-server-integrity-verification/index.js";
import "./implementations/k12-executable-content-response/index.js";
import "./implementations/k14-agent-credential-propagation/index.js";
import "./implementations/k16-unbounded-recursion/index.js";
// k20 migrated in chunk 1.6d but the import was never wired — surfaced during
// wave-2 integration. Re-importing after k-compliance-v2 ensures the per-rule
// v2 implementation supersedes the legacy K20Rule embedded in k-compliance-v2.
import "./implementations/k20-insufficient-audit-context/index.js";
import "./implementations/m-runtime-v2.js";
import "./implementations/compliance-remaining-detector.js";
