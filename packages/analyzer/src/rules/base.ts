/**
 * TypedRule Framework — v2
 *
 * Two tiers:
 * - TypedRule (v1): Legacy interface. Produces TypedFinding with optional metadata.
 *   Backward-compatible — existing rules continue working unchanged.
 *
 * - TypedRuleV2: New interface. MANDATORY evidence chains, declared requirements,
 *   analysis technique annotation. Every finding must prove its case with a
 *   structured source→propagation→sink chain that a regulator can audit.
 *
 * Migration path: Rules upgrade from TypedRule → TypedRuleV2 incrementally.
 * The engine wraps v1 rules in a V1Adapter so both interfaces dispatch identically.
 * Once all 177 rules are migrated, TypedRule and the adapter are removed.
 *
 * YAML files remain for metadata only (id, severity, owasp, mitre, remediation,
 * test_cases, framework mappings). ALL detection logic is TypeScript.
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

// ─── v2 Rule Interface ──────────────────────────────────────────────────────

/**
 * TypedRuleV2 — the target interface for all detection rules.
 *
 * Key differences from TypedRule (v1):
 * 1. `chain: EvidenceChain` is MANDATORY on every finding
 * 2. `requires` declares data needs — engine skips when data unavailable
 * 3. `technique` declares analysis method — no more hiding regex behind "TypedRule"
 * 4. Confidence is derived from chain, not a hardcoded number
 * 5. `evidence: string` is rendered from the chain (backward compat)
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

// ─── v1 Legacy Interface (backward-compatible) ─────────────────────────────

/** A single finding produced by a v1 typed rule */
export interface TypedFinding {
  rule_id: string;
  severity: Severity;
  evidence: string;
  remediation: string;
  owasp_category: OwaspCategory | null;
  mitre_technique: string | null;
  /** Confidence score 0.0–1.0 for Bayesian aggregation */
  confidence: number;
  /** Structured metadata for downstream analysis */
  metadata?: Record<string, unknown>;
}

/** Base interface for v1 typed detection rules (legacy — migrate to TypedRuleV2) */
export interface TypedRule {
  /** Rule identifier matching YAML definition (e.g., "C1", "A6") */
  readonly id: string;

  /** Human-readable rule name */
  readonly name: string;

  /** Execute the rule against an analysis context, returning zero or more findings */
  analyze(context: AnalysisContext): TypedFinding[];
}

// ─── v1 → v2 Adapter ────────────────────────────────────────────────────────

/**
 * Wraps a TypedRule (v1) as a TypedRuleV2 for unified engine dispatch.
 * Extracts evidence_chain from metadata if present, otherwise creates a
 * minimal chain from the flat evidence string.
 *
 * This adapter exists ONLY for migration. Once a rule is rewritten as
 * TypedRuleV2, remove its v1 implementation and this adapter is bypassed.
 */
export class V1RuleAdapter implements TypedRuleV2 {
  readonly id: string;
  readonly name: string;
  readonly requires: RuleRequirements = { tools: true }; // conservative default
  readonly technique: AnalysisTechnique = "structural";  // conservative default

  constructor(private readonly v1Rule: TypedRule) {
    this.id = v1Rule.id;
    this.name = v1Rule.name;
  }

  analyze(context: AnalysisContext): RuleResult[] {
    const v1Findings = this.v1Rule.analyze(context);
    return v1Findings.map((f) => {
      // If the v1 rule already produced an evidence chain, use it
      const existingChain = f.metadata?.evidence_chain as EvidenceChain | undefined;
      if (existingChain && existingChain.links && existingChain.confidence_factors) {
        return {
          rule_id: f.rule_id,
          severity: f.severity,
          owasp_category: f.owasp_category,
          mitre_technique: f.mitre_technique,
          remediation: f.remediation,
          chain: existingChain,
        };
      }

      // Otherwise create a minimal chain from flat evidence string.
      // This is intentionally low-confidence to flag rules needing migration.
      const minimalChain: EvidenceChain = {
        links: [
          {
            type: "source" as const,
            source_type: "file-content" as const,
            location: "unknown",
            observed: f.evidence.slice(0, 200),
            rationale: "V1 adapter — rule needs migration to TypedRuleV2 for structured evidence",
          },
          {
            type: "sink" as const,
            sink_type: "code-evaluation" as const,
            location: "unknown",
            observed: f.evidence.slice(0, 200),
          },
        ],
        confidence_factors: [
          {
            factor: "v1_adapter",
            adjustment: -0.15,
            rationale: "Finding produced by v1 rule without structured evidence chain",
          },
        ],
        confidence: Math.min(f.confidence, 0.55), // Cap v1 findings lower
      };

      return {
        rule_id: f.rule_id,
        severity: f.severity,
        owasp_category: f.owasp_category,
        mitre_technique: f.mitre_technique,
        remediation: f.remediation,
        chain: minimalChain,
      };
    });
  }
}

// ─── Utility: Convert RuleResult to TypedFinding (backward compat) ──────────

/**
 * Convert a v2 RuleResult back to a v1 TypedFinding for backward compatibility
 * with the existing pipeline, scorer, and persistence layer.
 *
 * The evidence field is rendered from the chain narrative. Confidence is
 * extracted from the chain. The chain itself is preserved in metadata.
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
 * Dual registry: holds both v1 TypedRule and v2 TypedRuleV2 implementations.
 * The engine always dispatches through the v2 interface — v1 rules are
 * automatically wrapped in V1RuleAdapter at registration time.
 */
const typedRuleRegistry = new Map<string, TypedRule>();
const v2RuleRegistry = new Map<string, TypedRuleV2>();

/** Register a v1 typed rule implementation (legacy — use registerTypedRuleV2 for new rules) */
export function registerTypedRule(rule: TypedRule): void {
  typedRuleRegistry.set(rule.id, rule);
  // Also register in v2 registry via adapter, but don't overwrite a native v2
  if (!v2RuleRegistry.has(rule.id)) {
    v2RuleRegistry.set(rule.id, new V1RuleAdapter(rule));
  }
}

/** Register a v2 typed rule implementation (preferred for all new rules) */
export function registerTypedRuleV2(rule: TypedRuleV2): void {
  v2RuleRegistry.set(rule.id, rule);
  // Also register a v1-compatible wrapper so the engine (which dispatches via
  // getTypedRule) can find this rule during the migration period.
  if (!typedRuleRegistry.has(rule.id)) {
    const v1Wrapper: TypedRule = {
      id: rule.id,
      name: rule.name,
      analyze(context) {
        return rule.analyze(context).map(ruleResultToTypedFinding);
      },
    };
    typedRuleRegistry.set(rule.id, v1Wrapper);
  }
}

/** Look up a typed rule by ID (v1 interface — legacy callers) */
export function getTypedRule(id: string): TypedRule | undefined {
  return typedRuleRegistry.get(id);
}

/** Look up a v2 typed rule by ID (preferred — includes v1 rules via adapter) */
export function getTypedRuleV2(id: string): TypedRuleV2 | undefined {
  return v2RuleRegistry.get(id);
}

/** Get all registered v2 typed rules (includes adapted v1 rules) */
export function getAllTypedRulesV2(): TypedRuleV2[] {
  return Array.from(v2RuleRegistry.values());
}

/** Get all registered typed rules (v1 interface — legacy callers) */
export function getAllTypedRules(): TypedRule[] {
  return Array.from(typedRuleRegistry.values());
}

/** Check if a rule ID has a typed implementation (v1 or v2) */
export function hasTypedRule(id: string): boolean {
  return typedRuleRegistry.has(id) || v2RuleRegistry.has(id);
}

/** Check if a rule ID has a native v2 implementation (not just adapted v1) */
export function hasNativeV2Rule(id: string): boolean {
  const v2Rule = v2RuleRegistry.get(id);
  return v2Rule !== undefined && !(v2Rule instanceof V1RuleAdapter);
}

/**
 * Migration progress: how many rules have been upgraded from v1 → native v2.
 * Used by CI checks and the accuracy dashboard.
 */
export function migrationStats(): {
  total_registered: number;
  native_v2: number;
  adapted_v1: number;
  migration_ratio: number;
} {
  const total = v2RuleRegistry.size;
  let nativeV2 = 0;
  for (const rule of v2RuleRegistry.values()) {
    if (!(rule instanceof V1RuleAdapter)) nativeV2++;
  }
  return {
    total_registered: total,
    native_v2: nativeV2,
    adapted_v1: total - nativeV2,
    migration_ratio: total > 0 ? nativeV2 / total : 0,
  };
}

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
