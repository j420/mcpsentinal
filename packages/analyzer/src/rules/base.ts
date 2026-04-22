/**
 * TypedRuleV2 Framework
 *
 * All detection rules are TypedRuleV2 implementations. Every rule declares its
 * data requirements, its analysis technique, and produces findings with a
 * mandatory structured EvidenceChain (source → propagation → sink) that a
 * regulator can audit.
 *
 * Rules self-register via `registerTypedRuleV2(new MyRule())` at module load.
 * The engine dispatches through `getTypedRuleV2(ruleId)` and converts the
 * returned RuleResult[] to TypedFinding[] (the pipeline wire type) via
 * `ruleResultToTypedFinding` for persistence.
 *
 * YAML files remain for metadata only (id, severity, owasp, mitre, remediation,
 * test_cases, framework mappings). ALL detection logic is TypeScript.
 *
 * History: a v1 interface (TypedRule) and a V1RuleAdapter existed during the
 * migration period. Phase 1 chunk 1.28 deleted both along with the legacy YAML
 * detection-type dispatchers (regex / schema-check / behavioral / composite)
 * now that all 164 active rules are native TypedRuleV2 implementations.
 */

import type { AnalysisContext } from "../engine.js";
import type { Severity, OwaspCategory } from "@mcp-sentinel/database";
import type { EvidenceChain } from "../evidence.js";
import { renderEvidenceNarrative } from "../evidence.js";

// ─── Analysis Technique Taxonomy ─────────────────────────────────────────────

/**
 * Every rule declares its analysis technique. This is not cosmetic — the engine
 * uses it for coverage reporting, the scorer uses it for sub-score routing, and
 * the API exposes it so orgs can filter by analysis depth.
 *
 * If a rule combines techniques (e.g., AST taint + entropy), use "composite"
 * and list the sub-techniques in the rule's documentation.
 */
export type AnalysisTechnique =
  | "ast-taint"          // TypeScript compiler API → source→sink data flow proof
  | "capability-graph"   // Multi-signal tool classification → DFS/BFS graph analysis
  | "schema-inference"   // JSON Schema structural analysis → capability classification
  | "entropy"            // Shannon entropy + chi-squared + compression ratio
  | "similarity"         // Levenshtein/Damerau-Levenshtein/Jaro-Winkler ensemble
  | "linguistic"         // Noisy-OR probabilistic multi-signal scoring
  | "unicode"            // Codepoint analysis (homoglyphs, zero-width, confusables)
  | "structural"         // AST/config structural property checking (not regex)
  | "dependency-audit"   // CVE lookup + version analysis + package manifest parsing
  | "cross-module"       // Import/export resolution across files (module-graph.ts)
  | "composite"          // Combines 2+ techniques (declare which in rule docs)
  | "stub";              // Companion rule — parent rule emits findings for this ID

// ─── Rule Requirements ──────────────────────────────────────────────────────

/**
 * Declares what data a rule needs to run meaningfully. The engine checks these
 * BEFORE dispatch — if requirements aren't met, the rule is skipped (not run
 * with empty data to produce a misleading "no findings" result).
 *
 * This powers AnalysisCoverage: the engine knows exactly which rules were
 * applicable vs. skipped, giving orgs an honest confidence band on every score.
 */
export interface RuleRequirements {
  /** Rule needs source code to analyze (C-rules, K-rules, L-rules, etc.) */
  source_code?: boolean;
  /** Rule needs tool metadata (most A/B/F/G/I rules) */
  tools?: boolean;
  /** Rule needs dependency list (D-rules) */
  dependencies?: boolean;
  /** Rule needs live connection metadata (E-rules) */
  connection_metadata?: boolean;
  /** Rule needs initialize response fields (H2) */
  initialize_metadata?: boolean;
  /** Rule needs MCP resource declarations (I3-I5) */
  resources?: boolean;
  /** Rule needs MCP prompt declarations (I6) */
  prompts?: boolean;
  /** Rule needs MCP root declarations (I11) */
  roots?: boolean;
  /** Rule needs declared server capabilities (I7, I8, I12) */
  declared_capabilities?: boolean;
  /** Minimum number of tools required (e.g., I16 consent fatigue needs >10) */
  min_tools?: number;
  /** Rule needs scan history for this server (G6 rug-pull, I14 drift) */
  scan_history?: boolean;
}

// ─── v2 Finding (mandatory evidence chain) ──────────────────────────────────

/**
 * A finding that PROVES its case. Not "pattern matched at line 42" but a
 * structured chain showing WHERE untrusted data enters, HOW it propagates,
 * WHERE it reaches a dangerous operation, WHAT mitigations exist (or don't),
 * and HOW a reviewer can verify every link.
 *
 * This is what goes into compliance reports. Regulators (EU AI Act Art. 12,
 * ISO 27001 A.8.15, ISO 42001 A.8.1) require auditable evidence trails.
 */
export interface RuleResult {
  rule_id: string;
  severity: Severity;
  owasp_category: OwaspCategory | null;
  mitre_technique: string | null;
  remediation: string;

  /**
   * The structured evidence chain. MANDATORY — not optional metadata.
   * Must have at least one source link and one sink link.
   * Confidence is computed FROM the chain, not hardcoded.
   */
  chain: EvidenceChain;
}

// ─── TypedRuleV2 Interface ──────────────────────────────────────────────────

/**
 * The only rule interface. Every rule implements this.
 *
 * Contract:
 * 1. `chain: EvidenceChain` is MANDATORY on every finding
 * 2. `requires` declares data needs — engine skips when data unavailable
 * 3. `technique` declares analysis method — no regex behind a TypedRule class
 * 4. Confidence is derived from chain, not a hardcoded number
 * 5. `evidence: string` is rendered from the chain (via ruleResultToTypedFinding)
 */
export interface TypedRuleV2 {
  /** Rule identifier matching YAML definition (e.g., "C1", "K1") */
  readonly id: string;

  /** Human-readable rule name */
  readonly name: string;

  /**
   * What data this rule needs to produce meaningful findings.
   * Engine checks these before dispatch — rules with unmet requirements
   * are skipped and counted in AnalysisCoverage.rules_skipped_no_data.
   */
  readonly requires: RuleRequirements;

  /**
   * What analysis technique this rule uses. Must be genuine — a rule that
   * wraps regex.exec() in a TypedRuleV2 class is still "regex", not "structural".
   * The engine tracks technique distribution per scan for coverage reporting.
   */
  readonly technique: AnalysisTechnique;

  /**
   * Execute the rule against an analysis context.
   * Returns zero or more findings, each with a mandatory evidence chain.
   *
   * Contract:
   * - Every finding's chain must have ≥1 source link and ≥1 sink link
   * - Confidence must be between 0.05 and 0.99
   * - Verification steps should point to specific locations (not "review the code")
   * - Return [] when no findings — never throw (engine has try-catch, but be clean)
   */
  analyze(context: AnalysisContext): RuleResult[];
}

// ─── Pipeline Wire Type ─────────────────────────────────────────────────────

/**
 * The flat finding shape used by the scoring + persistence layers. Produced
 * from a RuleResult via `ruleResultToTypedFinding`. Not a separate rule
 * interface — just the marshalling shape that flows through the engine into
 * the database.
 */
export interface TypedFinding {
  rule_id: string;
  severity: Severity;
  evidence: string;
  remediation: string;
  owasp_category: OwaspCategory | null;
  mitre_technique: string | null;
  /** Confidence score 0.0–1.0 for Bayesian aggregation */
  confidence: number;
  /** Structured metadata for downstream analysis (includes evidence_chain) */
  metadata?: Record<string, unknown>;
}

// ─── Utility: Convert RuleResult to TypedFinding ────────────────────────────

/**
 * Flatten a RuleResult (with structured chain) into a TypedFinding (the wire
 * type consumed by the scorer, the API, and the database). The chain narrative
 * is rendered into `evidence`, chain confidence is lifted to the top level,
 * and the chain itself is preserved verbatim in `metadata.evidence_chain`.
 */
export function ruleResultToTypedFinding(result: RuleResult): TypedFinding {
  return {
    rule_id: result.rule_id,
    severity: result.severity,
    evidence: renderEvidenceNarrative(result.chain),
    remediation: result.remediation,
    owasp_category: result.owasp_category,
    mitre_technique: result.mitre_technique,
    confidence: result.chain.confidence,
    metadata: { evidence_chain: result.chain },
  };
}

// ─── Registry ───────────────────────────────────────────────────────────────

/**
 * Single registry of TypedRuleV2 implementations keyed by rule_id.
 * Populated via side-effect imports from `rules/index.ts` — each rule
 * implementation calls `registerTypedRuleV2(new MyRule())` at module load.
 */
const v2RuleRegistry = new Map<string, TypedRuleV2>();

/** Register a TypedRuleV2 implementation. Overwrites any prior registration for the same id. */
export function registerTypedRuleV2(rule: TypedRuleV2): void {
  v2RuleRegistry.set(rule.id, rule);
}

/** Look up a TypedRuleV2 implementation by rule id. */
export function getTypedRuleV2(id: string): TypedRuleV2 | undefined {
  return v2RuleRegistry.get(id);
}

/** All registered TypedRuleV2 implementations. */
export function getAllTypedRulesV2(): TypedRuleV2[] {
  return Array.from(v2RuleRegistry.values());
}

// ─── Test/Helper Convenience ────────────────────────────────────────────────
//
// The analyzer test suite (~19 files) and mcp-sentinel-scanner's smoke test
// look up rules by id and call `.analyze(context)` expecting the flat
// TypedFinding[] shape used throughout the pipeline. These three helpers wrap
// the v2 registry with an auto-conversion so call sites don't all need to
// pipe through `ruleResultToTypedFinding` manually. They are thin delegators
// — no interface, no adapter class, no second registry.

/** Rule handle whose `.analyze()` returns the flat TypedFinding[] wire shape. */
export interface TypedRuleHandle {
  readonly id: string;
  readonly name: string;
  analyze(context: AnalysisContext): TypedFinding[];
}

function toHandle(rule: TypedRuleV2): TypedRuleHandle {
  return {
    id: rule.id,
    name: rule.name,
    analyze(context) {
      return rule.analyze(context).map(ruleResultToTypedFinding);
    },
  };
}

/** Look up a rule by id and return a handle whose `.analyze()` yields TypedFinding[]. */
export function getTypedRule(id: string): TypedRuleHandle | undefined {
  const rule = v2RuleRegistry.get(id);
  return rule ? toHandle(rule) : undefined;
}

/** All registered rules as TypedRuleHandles (flat-finding shape). */
export function getAllTypedRules(): TypedRuleHandle[] {
  return Array.from(v2RuleRegistry.values(), toHandle);
}

/** Whether a rule with the given id is registered. */
export function hasTypedRule(id: string): boolean {
  return v2RuleRegistry.has(id);
}

// ─── Requirement Checking ──────────────────────────────────────────────────

/**
 * Check if a rule's requirements are met by the given analysis context.
 * Returns { met: true } or { met: false, missing: string[] }.
 */
export function checkRequirements(
  requires: RuleRequirements,
  context: AnalysisContext,
): { met: boolean; missing: string[] } {
  const missing: string[] = [];

  if (requires.source_code && !context.source_code) missing.push("source_code");
  if (requires.tools && (!context.tools || context.tools.length === 0)) missing.push("tools");
  if (requires.dependencies && (!context.dependencies || context.dependencies.length === 0)) missing.push("dependencies");
  if (requires.connection_metadata && !context.connection_metadata) missing.push("connection_metadata");
  if (requires.initialize_metadata && !context.initialize_metadata) missing.push("initialize_metadata");
  if (requires.resources && (!context.resources || context.resources.length === 0)) missing.push("resources");
  if (requires.prompts && (!context.prompts || context.prompts.length === 0)) missing.push("prompts");
  if (requires.roots && (!context.roots || context.roots.length === 0)) missing.push("roots");
  if (requires.declared_capabilities && !context.declared_capabilities) missing.push("declared_capabilities");
  if (requires.min_tools && (!context.tools || context.tools.length < requires.min_tools)) {
    missing.push(`min_tools(${requires.min_tools})`);
  }
  // scan_history is checked separately by the engine (needs DB access)

  return { met: missing.length === 0, missing };
}
