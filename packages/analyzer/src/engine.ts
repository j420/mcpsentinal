import type { DetectionRule, FindingInput } from "@mcp-sentinel/database";
import pino from "pino";
import type { ServerToolPin } from "./tool-fingerprint.js";
import {
  getTypedRuleV2,
  getAllTypedRulesV2,
  checkRequirements,
  ruleResultToTypedFinding,
  type TypedFinding,
  type AnalysisTechnique,
} from "./rules/base.js";
// Side-effect import: registers all TypedRuleV2 implementations so the engine
// can dispatch to them when YAML rules declare detect.type: "typed".
import "./rules/index.js";
import { CodeAnalyzer } from "./engines/code-analyzer.js";
import { DescriptionAnalyzer } from "./engines/description-analyzer.js";
import { SchemaAnalyzer } from "./engines/schema-analyzer.js";
import { DependencyAnalyzer } from "./engines/dependency-analyzer.js";
import { ProtocolAnalyzer } from "./engines/protocol-analyzer.js";
// Phase 1 rebuild: profile-aware analysis
import { profileServer, type ServerProfile } from "./profiler.js";
import { annotateFindings, scoredFindings, unscoredFindings, generateProfileReport, type AnnotatedFinding, type ScoredFinding } from "./relevance.js";
import { selectThreats, getRelevantRuleIds, type ThreatDefinition } from "./threat-model.js";

// Log to stderr so that stdout is clean for callers that parse it (e.g. CLI --json mode)
const logger = pino({ name: "analyzer:engine" }, process.stderr);

export interface AnalysisContext {
  server: {
    id: string;
    name: string;
    description: string | null;
    github_url: string | null;
  };
  tools: Array<{
    name: string;
    description: string | null;
    input_schema: Record<string, unknown> | null;
    /** MCP 2025-11-25 spec: structured output schema for tool results — J3 injection surface */
    output_schema?: Record<string, unknown> | null;
    /** MCP 2025-03-26 spec: tool behaviour hints used by I1/I2 annotation rules */
    annotations?: {
      readOnlyHint?: boolean;
      destructiveHint?: boolean;
      idempotentHint?: boolean;
      openWorldHint?: boolean;
    } | null;
  }>;
  source_code: string | null;
  /** Per-file source map for cross-module analysis. Keys are file paths, values are source content. */
  source_files?: Map<string, string> | null;
  dependencies: Array<{
    name: string;
    version: string | null;
    has_known_cve: boolean;
    cve_ids: string[];
    last_updated: Date | null;
  }>;
  connection_metadata: {
    auth_required: boolean;
    transport: string;
    response_time_ms: number;
  } | null;
  // H2: Fields from the MCP initialize response (serverInfo.name is in server.name)
  initialize_metadata?: {
    server_version?: string | null;
    server_instructions?: string | null;
  };
  // Category I: Protocol surface data
  resources?: Array<{
    uri: string;
    name: string;
    description?: string | null;
    mimeType?: string | null;
  }>;
  prompts?: Array<{
    name: string;
    description?: string | null;
    arguments?: Array<{
      name: string;
      description?: string | null;
      required?: boolean;
    }>;
  }>;
  roots?: Array<{
    uri: string;
    name?: string | null;
  }>;
  declared_capabilities?: {
    tools?: boolean;
    resources?: boolean;
    prompts?: boolean;
    sampling?: boolean;
    logging?: boolean;
  } | null;
  /** Tool pin from previous scan for drift detection (G6 enhancement) */
  previous_tool_pin?: ServerToolPin | null;
}

/**
 * Analysis coverage — tells orgs EXACTLY what was analyzed and what was skipped.
 * Without this, a score of 85 with no source code looks identical to 85 with
 * full taint analysis. Regulators (EU AI Act Art. 12, ISO 42001 A.8.1) require
 * transparency about the scope and limitations of any assessment.
 */
export interface AnalysisCoverage {
  /** Whether source code was available for analysis */
  had_source_code: boolean;
  /** Whether a live MCP connection was established */
  had_connection: boolean;
  /** Whether dependency data was available */
  had_dependencies: boolean;
  /** Whether initialize metadata (H2 surface) was available */
  had_initialize_metadata: boolean;
  /** Whether MCP resources were available (I3-I5) */
  had_resources: boolean;
  /** Whether MCP prompts were available (I6) */
  had_prompts: boolean;
  /** Whether declared capabilities were available (I7, I12) */
  had_declared_capabilities: boolean;

  /** Analysis techniques that were actually applied */
  techniques_run: AnalysisTechnique[];
  /** Number of v2 rules whose requirements were met */
  rules_applicable: number;
  /** Number of v2 rules that actually executed */
  rules_executed: number;
  /** Number of v2 rules skipped due to missing data (with reasons) */
  rules_skipped_no_data: number;
  /** Rules that skipped, with the specific missing data for each */
  skip_reasons: Array<{ rule_id: string; missing: string[] }>;
  /** Number of rules that produced at least one finding */
  rules_with_findings: number;

  /** rules_executed / rules_applicable — how much of the analysis surface was covered */
  coverage_ratio: number;

  /**
   * Confidence band based on coverage:
   * - high: coverage_ratio >= 0.80 AND had_source_code AND had_connection
   * - medium: coverage_ratio >= 0.60
   * - low: coverage_ratio >= 0.30
   * - minimal: < 0.30
   */
  confidence_band: "high" | "medium" | "low" | "minimal";
}

/** Result of profile-aware analysis — includes profiling, threat mapping, and relevance filtering */
export interface ProfiledAnalysisResult {
  /** Server capability profile with evidence */
  profile: ServerProfile;
  /** Threats applicable to this server */
  threats: ThreatDefinition[];
  /** Findings that are relevant AND meet evidence standards — these affect the score */
  scored_findings: ScoredFinding[];
  /** Findings that were generated but aren't relevant or don't meet evidence standards */
  informational_findings: AnnotatedFinding[];
  /** All findings with full annotations */
  all_annotated: AnnotatedFinding[];
  /** Human-readable profile report */
  profile_report: string;
  /** What was analyzed, what was skipped, and why — enables honest confidence reporting */
  coverage: AnalysisCoverage;
}

export class AnalysisEngine {
  private codeAnalyzer = new CodeAnalyzer();
  private descriptionAnalyzer = new DescriptionAnalyzer();
  private schemaAnalyzer = new SchemaAnalyzer();
  private dependencyAnalyzer = new DependencyAnalyzer();
  private protocolAnalyzer = new ProtocolAnalyzer();

  constructor(private rules: DetectionRule[]) {}

  /**
   * Profile-aware analysis: profiles the server, selects relevant threats,
   * runs rules, and returns annotated findings with evidence chains.
   *
   * This is the new recommended entry point. The original analyze() is preserved
   * for backward compatibility and is called internally.
   */
  analyzeWithProfile(context: AnalysisContext): ProfiledAnalysisResult {
    // Step 1: Profile the server
    const profile = profileServer(context);
    logger.info(
      {
        server: context.server.id,
        capabilities: profile.capabilities
          .filter((c) => c.confidence >= 0.5)
          .map((c) => `${c.capability}(${(c.confidence * 100).toFixed(0)}%)`),
        attack_surfaces: profile.attack_surfaces,
        data_flow_pairs: profile.data_flow_pairs.length,
      },
      "Server profiled",
    );

    // Step 2: Select relevant threats and rule IDs
    const threats = selectThreats(profile);
    const relevantRuleIds = getRelevantRuleIds(profile);
    logger.info(
      {
        server: context.server.id,
        threats: threats.map((t) => t.id),
        relevant_rules: relevantRuleIds.size,
        total_rules: this.rules.length,
      },
      "Threat model selected",
    );

    // Step 3: Run ALL rules via analyzeRich() — preserves confidence + metadata
    // from TypedRules (e.g., C1's AST taint confidence of 0.95 and evidence chains).
    // Legacy YAML rules get default confidence 0.5.
    const richFindings = this.analyzeRich(context);

    // Step 4: Annotate findings with relevance and threat context
    // annotateFindings() uses evidence_chain from metadata when available,
    // preserving the real confidence computed by the rule.
    const annotated = annotateFindings(richFindings, profile);

    // Step 5: Separate scored vs. informational findings
    const scored = scoredFindings(annotated);
    const unscored = unscoredFindings(annotated);

    // Step 6: Generate profile report
    const profileReport = generateProfileReport(profile);

    // Step 7: Compute analysis coverage — what was analyzed, what was skipped
    const coverage = this.computeCoverage(context, richFindings);

    logger.info(
      {
        server: context.server.id,
        total_findings: richFindings.length,
        scored_findings: scored.length,
        unscored_findings: unscored.length,
        filtered_out: richFindings.length - scored.length,
        coverage_ratio: coverage.coverage_ratio.toFixed(2),
        confidence_band: coverage.confidence_band,
        techniques: coverage.techniques_run,
        rules_skipped: coverage.rules_skipped_no_data,
      },
      "Profile-aware analysis complete",
    );

    return {
      profile,
      threats,
      scored_findings: scored,
      informational_findings: unscored,
      all_annotated: annotated,
      profile_report: profileReport,
      coverage,
    };
  }

  analyze(context: AnalysisContext): FindingInput[] {
    return this.analyzeRich(context).map((f) => ({
      rule_id: f.rule_id,
      severity: f.severity as FindingInput["severity"],
      evidence: f.evidence,
      remediation: f.remediation,
      owasp_category: f.owasp_category as FindingInput["owasp_category"],
      mitre_technique: f.mitre_technique,
    }));
  }

  /**
   * Internal enriched analysis — preserves confidence and metadata from
   * TypedRules and engines. Used by analyzeWithProfile() to avoid losing
   * evidence chain data through FindingInput conversion.
   */
  private analyzeRich(context: AnalysisContext): TypedFinding[] {
    const findings: TypedFinding[] = [];

    // ── Phase 1: Specialized engines (real analysis) ──
    // Each engine owns a category and does actual program analysis,
    // structural inference, or linguistic analysis — not regex.
    // Only include findings for rules that are actually loaded.
    const loadedRuleIds = new Set(this.rules.map((r) => r.id));
    const engineFindings: TypedFinding[] = [];
    const engineRuleIds = new Set<string>();

    const allEngineResults: Array<{
      rule_id: string;
      severity: string;
      evidence: string;
      remediation: string;
      owasp_category: string | null;
      mitre_technique: string | null;
      confidence?: number;
      metadata?: Record<string, unknown>;
    }> = [];

    try { allEngineResults.push(...this.codeAnalyzer.analyze(context)); }
    catch (err) { logger.error({ err }, "CodeAnalyzer error"); }

    try { allEngineResults.push(...this.descriptionAnalyzer.analyze(context)); }
    catch (err) { logger.error({ err }, "DescriptionAnalyzer error"); }

    try { allEngineResults.push(...this.schemaAnalyzer.analyze(context)); }
    catch (err) { logger.error({ err }, "SchemaAnalyzer error"); }

    try { allEngineResults.push(...this.dependencyAnalyzer.analyze(context)); }
    catch (err) { logger.error({ err }, "DependencyAnalyzer error"); }

    try { allEngineResults.push(...this.protocolAnalyzer.analyze(context)); }
    catch (err) { logger.error({ err }, "ProtocolAnalyzer error"); }

    // Filter to only rules that are loaded, then convert to TypedFinding.
    // When a rule is loaded as detect.type="typed" AND has a TypedRuleV2
    // implementation, skip the engine finding and let the TypedRuleV2 run
    // in Phase 2 — TypedRuleV2s produce structured evidence chains that
    // the older engines don't. This ensures confidence and evidence_chain
    // data survive through the pipeline.
    const typedRuleIds = new Set(
      this.rules
        .filter((r) => r.detect.type === "typed" && getTypedRuleV2(r.id) !== undefined)
        .map((r) => r.id)
    );

    let deferredToTypedRule = 0;
    for (const f of allEngineResults) {
      if (!loadedRuleIds.has(f.rule_id)) continue;

      // Defer to TypedRule — it produces evidence chains
      if (typedRuleIds.has(f.rule_id)) {
        deferredToTypedRule++;
        continue;
      }

      engineFindings.push({
        rule_id: f.rule_id,
        severity: f.severity as TypedFinding["severity"],
        evidence: f.evidence,
        remediation: f.remediation,
        owasp_category: f.owasp_category as TypedFinding["owasp_category"],
        mitre_technique: f.mitre_technique,
        confidence: f.confidence ?? 0.5,
        metadata: f.metadata,
      });
      engineRuleIds.add(f.rule_id);
    }

    findings.push(...engineFindings);

    // ── Phase 2: YAML rules (fallback for rules not covered by engines) ──
    // Engines cover: C1-C16, A1-A9, B1-B7, D1-D7, E1-E4, F1-F7, G1, H1-H3, I1-I2, I7, I16, J1, J5, K5
    // YAML fallback covers: G2-G7, I3-I6, I8-I15, J2-J4, J6-J7, K1-K4, K6-K20, L-Q
    let typedRulesRun = 0;
    let yamlRulesRun = 0;

    for (const rule of this.rules) {
      // Skip rules already handled by specialized engines
      if (engineRuleIds.has(rule.id)) continue;

      try {
        const yamlFindings = this.runRule(rule, context);
        findings.push(...yamlFindings);
        yamlRulesRun++;
      } catch (err) {
        logger.error(
          { rule: rule.id, server: context.server.id, err },
          "Rule execution error"
        );
      }
    }

    logger.info(
      {
        server: context.server.id,
        engine_findings: engineFindings.length,
        engine_rules: engineRuleIds.size,
        deferred_to_typed_rule: deferredToTypedRule,
        yaml_fallback_rules: yamlRulesRun,
        total_findings: findings.length,
      },
      "Analysis complete"
    );

    return findings;
  }

  /**
   * Compute analysis coverage by checking every registered v2 rule's requirements
   * against the context. This tells orgs exactly what was analyzed and what was
   * skipped due to missing data.
   */
  private computeCoverage(context: AnalysisContext, findings: TypedFinding[]): AnalysisCoverage {
    const allV2Rules = getAllTypedRulesV2();
    const techniquesRun = new Set<AnalysisTechnique>();
    const skipReasons: Array<{ rule_id: string; missing: string[] }> = [];
    let rulesApplicable = 0;
    let rulesExecuted = 0;
    let rulesSkippedNoData = 0;

    for (const rule of allV2Rules) {
      const check = checkRequirements(rule.requires, context);
      rulesApplicable++;
      if (check.met) {
        rulesExecuted++;
        techniquesRun.add(rule.technique);
      } else {
        rulesSkippedNoData++;
        skipReasons.push({ rule_id: rule.id, missing: check.missing });
      }
    }

    // Count rules that produced findings
    const ruleIdsWithFindings = new Set(findings.map((f) => f.rule_id));
    const rulesWithFindings = ruleIdsWithFindings.size;

    const coverageRatio = rulesApplicable > 0 ? rulesExecuted / rulesApplicable : 0;

    // Confidence band determination
    const hadSource = !!context.source_code;
    const hadConnection = !!context.connection_metadata;
    let confidenceBand: AnalysisCoverage["confidence_band"];
    if (coverageRatio >= 0.80 && hadSource && hadConnection) {
      confidenceBand = "high";
    } else if (coverageRatio >= 0.60) {
      confidenceBand = "medium";
    } else if (coverageRatio >= 0.30) {
      confidenceBand = "low";
    } else {
      confidenceBand = "minimal";
    }

    return {
      had_source_code: hadSource,
      had_connection: hadConnection,
      had_dependencies: context.dependencies.length > 0,
      had_initialize_metadata: !!context.initialize_metadata,
      had_resources: !!(context.resources && context.resources.length > 0),
      had_prompts: !!(context.prompts && context.prompts.length > 0),
      had_declared_capabilities: !!context.declared_capabilities,
      techniques_run: Array.from(techniquesRun),
      rules_applicable: rulesApplicable,
      rules_executed: rulesExecuted,
      rules_skipped_no_data: rulesSkippedNoData,
      skip_reasons: skipReasons,
      rules_with_findings: rulesWithFindings,
      coverage_ratio: Math.round(coverageRatio * 100) / 100,
      confidence_band: confidenceBand,
    };
  }

  private runRule(rule: DetectionRule, context: AnalysisContext): TypedFinding[] {
    if (rule.detect.type !== "typed") {
      logger.warn(
        { rule: rule.id, detect_type: rule.detect.type },
        "Non-typed rule detected — only typed rules are supported after chunk 1.28 cutover",
      );
      return [];
    }
    const impl = getTypedRuleV2(rule.id);
    if (!impl) {
      logger.warn({ rule: rule.id }, "Typed rule has no TypeScript implementation — skipping");
      return [];
    }
    const results = impl.analyze(context);
    return results.map(ruleResultToTypedFinding);
  }
}
