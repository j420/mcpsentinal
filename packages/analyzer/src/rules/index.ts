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
// f1-lethal-trifecta.ts removed in Phase 1 Chunk 1.25; its two primary rules
// (F1, F7) and its three stub companions (F2, F3, F6) have each been migrated
// to their own directory with full Rule Standard v2 charters.
import "./implementations/f1-lethal-trifecta/index.js";
import "./implementations/f2-high-risk-capability-profile/index.js";
import "./implementations/f3-data-flow-risk-source-sink/index.js";
import "./implementations/f6-circular-data-loop/index.js";
import "./implementations/f7-multi-step-exfiltration-chain/index.js";
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
// supply-chain-detector.ts deleted in Phase 1 Chunk 1.11; its four rules
// (L5, L12, L14 stub, K10) have each been migrated to their own directory.
// L5 emits L14 findings during its manifest scan (companion-rule pattern).
import "./implementations/l5-manifest-confusion/index.js";
import "./implementations/l12-build-artifact-tampering/index.js";
import "./implementations/l14-hidden-entry-point-mismatch/index.js";
import "./implementations/k10-package-registry-substitution/index.js";
// code-security-deep-detector.ts removed in Phase 1 Chunk 1.18; its four rules
// (C2, C5, C10, C14) have each been migrated to their own directory.
import "./implementations/c2-path-traversal/index.js";
import "./implementations/c5-hardcoded-secrets/index.js";
import "./implementations/c10-prototype-pollution/index.js";
import "./implementations/c14-jwt-algorithm-confusion/index.js";
// Chunk 1.9: L1/L2/L6/L13 migrated out of advanced-supply-chain-detector.ts
// into per-rule Rule Standard v2 directories. Chunk 1.10 (wave-3) completed
// the migration by moving L7, K3, K5, K8 and deleting the legacy detector.
import "./implementations/l1-github-actions-tag-poisoning/index.js";
import "./implementations/l2-malicious-build-plugin/index.js";
import "./implementations/l6-config-symlink-attack/index.js";
import "./implementations/l13-build-credential-file-theft/index.js";
import "./implementations/l7-transitive-mcp-delegation/index.js";
import "./implementations/k3-audit-log-tampering/index.js";
import "./implementations/k5-auto-approve-bypass/index.js";
import "./implementations/k8-cross-boundary-credential-sharing/index.js";
import "./implementations/ai-manipulation-detector.js";
// infrastructure-detector.ts deleted in Phase 1 Chunk 1.13; its seven rules
// (P1, P2, P3, P4, P5, P6, P7) have each been migrated to their own directory.
// P8, P9, P10 live in their own directories from wave-3 (chunk 1.12).
import "./implementations/p1-docker-socket-mount/index.js";
import "./implementations/p2-dangerous-container-capabilities/index.js";
import "./implementations/p3-cloud-metadata-access/index.js";
import "./implementations/p4-tls-bypass/index.js";
import "./implementations/p5-secrets-in-build-layers/index.js";
import "./implementations/p6-ld-preload-hijack/index.js";
import "./implementations/p7-host-filesystem-mount/index.js";
import "./implementations/protocol-ai-runtime-detector.js";
import "./implementations/data-privacy-cross-ecosystem-detector.js";
// description-schema-detector.ts deleted in Phase-1 chunk 1.20 — 13 rules
// (A1-A5, A8, B1-B7) migrated to per-rule Rule Standard v2 directories.
import "./implementations/a1-prompt-injection-description/index.js";
import "./implementations/a2-excessive-scope-claims/index.js";
import "./implementations/a3-suspicious-urls/index.js";
import "./implementations/a4-tool-name-shadowing/index.js";
import "./implementations/a5-description-length-anomaly/index.js";
import "./implementations/a8-description-capability-mismatch/index.js";
import "./implementations/b1-missing-input-validation/index.js";
import "./implementations/b2-dangerous-parameter-types/index.js";
import "./implementations/b3-excessive-parameter-count/index.js";
import "./implementations/b4-schemaless-tools/index.js";
import "./implementations/b5-prompt-injection-parameter/index.js";
import "./implementations/b6-unconstrained-additional-properties/index.js";
import "./implementations/b7-dangerous-default-values/index.js";
// dependency-behavioral-detector.ts deleted in Phase 1 Chunk 1.23; its ten
// rules (D1, D2, D4, D5, D6, D7, E1, E2, E3, E4) have each been migrated to
// their own directory. D-rules consume `context.dependencies[]`; E-rules
// consume `context.connection_metadata`. D3 was migrated earlier in wave-1
// chunk 1.24 (`d3-typosquatting/`).
import "./implementations/d1-known-cves/index.js";
import "./implementations/d2-abandoned-deps/index.js";
import "./implementations/d4-excessive-deps/index.js";
import "./implementations/d5-known-malicious-packages/index.js";
import "./implementations/d6-weak-cryptography/index.js";
import "./implementations/d7-dependency-confusion/index.js";
import "./implementations/e1-no-auth-required/index.js";
import "./implementations/e2-insecure-transport/index.js";
import "./implementations/e3-response-time-anomaly/index.js";
import "./implementations/e4-excessive-tool-count/index.js";
// ecosystem-adversarial-detector.ts deleted in Phase 1 Chunk 1.26; its five
// rules (F4, F5, G6, H1, H3) have each been migrated to their own directory
// with full Rule Standard v2 charters.
import "./implementations/f4-mcp-spec-non-compliance/index.js";
import "./implementations/f5-official-namespace-squatting/index.js";
import "./implementations/g6-rug-pull-tool-drift/index.js";
import "./implementations/h1-oauth-insecure-implementation/index.js";
import "./implementations/h3-multi-agent-propagation-risk/index.js";
import "./implementations/protocol-surface-remaining-detector.js";
import "./implementations/k1-absent-structured-logging/index.js";
import "./implementations/k4-missing-human-confirmation/index.js";
import "./implementations/k6-overly-broad-oauth-scopes/index.js";
import "./implementations/k7-long-lived-tokens/index.js";
import "./implementations/k17-missing-timeout/index.js";
import "./implementations/m4-tool-squatting/index.js";
import "./implementations/m5-context-window-flooding.js";
import "./implementations/l-supply-chain-v2.js";
import "./implementations/o4-q10-v2.js";
// docker-k8s-crypto-v2.ts deleted in Phase 1 Chunk 1.12; its five rules
// (L3, K19, P8, P9, P10) have each been migrated to their own directory.
import "./implementations/l3-dockerfile-base-image-risk/index.js";
import "./implementations/k19-missing-runtime-sandbox/index.js";
import "./implementations/p8-ecb-mode-static-iv/index.js";
import "./implementations/p9-excessive-container-resources/index.js";
import "./implementations/p10-network-host-mode/index.js";
// code-remaining-detector.ts deleted in Phase 1 Chunk 1.19; its seven rules
// (C3, C6, C7, C8, C9, C11, C15) have each been migrated to their own directory.
// C3 SSRF reuses _shared/taint-rule-kit/; C11 ReDoS uses a hand-coded
// character-walker (a regex-based detector would itself be ReDoS-vulnerable).
import "./implementations/c3-ssrf/index.js";
import "./implementations/c6-error-leakage/index.js";
import "./implementations/c7-wildcard-cors/index.js";
import "./implementations/c8-no-auth-network/index.js";
import "./implementations/c9-excessive-fs-scope/index.js";
import "./implementations/c11-redos/index.js";
import "./implementations/c15-timing-attack/index.js";
// Phase 1 chunk 1.8: N1-N3, N7, N8, N10 migrated out of jsonrpc-protocol-v2.ts
// into per-rule Rule Standard v2 directories. The legacy file is deleted.
import "./implementations/n1-jsonrpc-batch-request-abuse/index.js";
import "./implementations/n2-jsonrpc-notification-flooding/index.js";
import "./implementations/n3-jsonrpc-id-collision/index.js";
import "./implementations/n7-progress-token-abuse/index.js";
import "./implementations/n8-cancellation-race-condition/index.js";
import "./implementations/n10-incomplete-handshake-dos/index.js";
// k-compliance-v2.ts deleted in Phase 1 Chunk 1.6/D (wave-6); K12 and K20
// now have their own per-rule Rule Standard v2 directories. K14 and K16
// were migrated earlier in chunks 1.6b and 1.6c.
import "./implementations/k11-missing-server-integrity-verification/index.js";
import "./implementations/k12-executable-content-response/index.js";
import "./implementations/k14-agent-credential-propagation/index.js";
import "./implementations/k16-unbounded-recursion/index.js";
import "./implementations/k20-insufficient-audit-context/index.js";
import "./implementations/m-runtime-v2.js";
import "./implementations/compliance-remaining-detector.js";
