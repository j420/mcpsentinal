import type { FindingInput, Severity, RiskDomain } from "@mcp-sentinel/database";
import pino from "pino";

// Log to stderr so that stdout is clean for callers that parse it (e.g. CLI --json mode)
const logger = pino({ name: "scorer" }, process.stderr);

/**
 * Analysis coverage summary — passed from the engine to the scorer so that
 * scores can be reported with honest confidence bands.
 *
 * Without this, "85/100 with no source code" is indistinguishable from
 * "85/100 with full AST taint analysis". Regulators require transparency.
 */
export interface AnalysisCoverageInput {
  had_source_code: boolean;
  had_connection: boolean;
  had_dependencies: boolean;
  coverage_ratio: number;
  confidence_band: "high" | "medium" | "low" | "minimal";
  techniques_run: string[];
  rules_executed: number;
  rules_skipped_no_data: number;
}

export interface ScoreResult {
  total_score: number;

  // ── Legacy sub-scores (5 — backward-compatible, kept for DB/API compat) ──
  code_score: number;
  deps_score: number;
  config_score: number;        // Still computed — sum of all categories that map here
  description_score: number;
  behavior_score: number;

  // ── v2 sub-scores (8 — balanced, no single bucket absorbs 141 rules) ──
  // These REPLACE config_score for meaningful per-domain analysis.
  // config_score is still computed for backward compat but should be
  // deprecated in API responses once v2 scores are adopted.
  schema_score: number;        // B1-B7 (schema inference)
  ecosystem_score: number;     // E1-E4, F1-F7, I13 (capability graph + behavioral)
  protocol_score: number;      // H1-H3, I1-I16 (structural + protocol surface)
  adversarial_score: number;   // G1-G7, J1-J7 (adversarial + threat intel)
  compliance_score: number;    // K1-K20 (framework-mapped compliance)
  supply_chain_score: number;  // L1-L15, D1-D7 (supply chain + deps combined)
  infrastructure_score: number; // M1-M9, N1-N15, O1-O10, P1-P10, Q1-Q15

  owasp_coverage: Record<string, boolean>;
  penalty_breakdown: Array<{
    rule_id: string;
    severity: string;
    penalty: number;
  }>;

  // ── Phase 0, chunk 0.2: shadow score from engine_v2 rules only ──────────
  // `total_score_v2` is the same `100 - Σ penalty` computation applied
  // ONLY to findings whose rule was flagged `engine_v2: true` in YAML.
  // Null means no rule has flipped to v2 yet — the shadow score is not
  // meaningful until there is at least one contributing rule.
  total_score_v2: number | null;
  // Per-rule attribution of the techniques observed for v2 findings. Empty
  // map when no v2 rules are active. Value is the rule's category (until a
  // finer-grained AnalysisTechnique tag is threaded through in Phase 1.2).
  techniques_v2: Record<string, string>;

  /**
   * Analysis coverage from the engine — included when the caller provides it.
   * Tells orgs: "This score of 85 is based on [high/medium/low/minimal] coverage."
   *
   * Display format: "85/100 (high confidence)" or "85/100 (low confidence)"
   * Tooltip: "Analyzed: source code ✓, live connection ✓, dependencies ✓, 142/177 rules executed"
   */
  analysis_coverage?: AnalysisCoverageInput;
}

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  informational: 1,
};

const CATEGORY_MAP: Record<string, keyof Pick<ScoreResult, "code_score" | "deps_score" | "config_score" | "description_score" | "behavior_score">> = {
  "code-analysis": "code_score",
  "dependency-analysis": "deps_score",
  "behavioral-analysis": "behavior_score",
  "description-analysis": "description_score",
  "schema-analysis": "config_score",
  "ecosystem-context": "config_score",
  "adversarial-ai": "config_score",
  "2026-attack-surface": "config_score",        // H2–H3 (currently use adversarial-ai, but enum exists)
  "auth-analysis": "config_score",
  "protocol-surface": "config_score",
  "threat-intelligence": "config_score",       // J1–J7 (CVE-backed)
  "compliance-governance": "config_score",     // K1–K20 (framework-mapped)
  "supply-chain-advanced": "config_score",     // L1–L15 (CI/CD, build, config)
  "ai-runtime-exploitation": "config_score",   // M1–M9 (token injection, reasoning)
  "protocol-edge-cases": "config_score",       // N1–N15 (JSON-RPC, transport)
  "data-privacy-attacks": "config_score",      // O1–O10 (steganography, covert channels)
  "infrastructure-runtime": "config_score",    // P1–P10 (containers, cloud metadata)
  "cross-ecosystem-emergent": "config_score",  // Q1–Q15 (protocol bridges, IDE)
};

// ─── v2 Category Map (8 balanced sub-scores) ────────────────────────────────
// Each rule category maps to a SPECIFIC sub-score — no single bucket absorbs
// 141 rules. This gives organizations meaningful per-domain visibility.
type V2ScoreKey = "code_score" | "description_score" | "schema_score" | "ecosystem_score"
  | "protocol_score" | "adversarial_score" | "compliance_score" | "supply_chain_score"
  | "infrastructure_score";

const CATEGORY_MAP_V2: Record<string, V2ScoreKey> = {
  "code-analysis": "code_score",              // C1-C16 (AST taint)
  "description-analysis": "description_score", // A1-A9 (linguistic + entropy)
  "schema-analysis": "schema_score",           // B1-B7 (schema inference)
  "dependency-analysis": "supply_chain_score", // D1-D7 (CVE + similarity)
  "behavioral-analysis": "ecosystem_score",    // E1-E4 (behavioral thresholds)
  "ecosystem-context": "ecosystem_score",      // F1-F7 (capability graph)
  "adversarial-ai": "adversarial_score",       // G1-G7 (AI-native attacks)
  "2026-attack-surface": "protocol_score",     // H1-H3 (OAuth, init injection, multi-agent)
  "auth-analysis": "protocol_score",           // Auth-related protocol checks
  "protocol-surface": "protocol_score",        // I1-I16 (MCP protocol surface)
  "threat-intelligence": "adversarial_score",  // J1-J7 (CVE-backed threat intel)
  "compliance-governance": "compliance_score",  // K1-K20 (8-framework mapped)
  "supply-chain-advanced": "supply_chain_score", // L1-L15 (CI/CD, build, config)
  "ai-runtime-exploitation": "infrastructure_score", // M1-M9 (token injection, reasoning)
  "protocol-edge-cases": "infrastructure_score",     // N1-N15 (JSON-RPC, transport)
  "data-privacy-attacks": "infrastructure_score",    // O1-O10 (steganography, covert channels)
  "infrastructure-runtime": "infrastructure_score",  // P1-P10 (containers, cloud metadata)
  "cross-ecosystem-emergent": "infrastructure_score", // Q1-Q15 (protocol bridges, IDE)
};

// ─── Risk Domain → v2 Sub-Score Mapping ─────────────────────────────────────
// 13 framework-driven risk domains mapped to the 8 v2 sub-scores.
const RISK_DOMAIN_MAP: Record<RiskDomain, V2ScoreKey> = {
  "prompt-injection": "description_score",
  "tool-poisoning": "adversarial_score",
  "code-vulnerabilities": "code_score",
  "data-exfiltration": "adversarial_score",
  "authentication": "protocol_score",
  "supply-chain-security": "supply_chain_score",
  "human-oversight": "compliance_score",
  "audit-logging": "compliance_score",
  "multi-agent-security": "protocol_score",
  "protocol-transport": "protocol_score",
  "denial-of-service": "infrastructure_score",
  "container-runtime": "infrastructure_score",
  "model-manipulation": "adversarial_score",
};

const OWASP_CATEGORIES = [
  "MCP01-prompt-injection",
  "MCP02-tool-poisoning",
  "MCP03-command-injection",
  "MCP04-data-exfiltration",
  "MCP05-privilege-escalation",
  "MCP06-excessive-permissions",
  "MCP07-insecure-config",
  "MCP08-dependency-vuln",
  "MCP09-logging-monitoring",
  "MCP10-supply-chain",
];

/** Finding with confidence for weighted scoring.
 *  FindingInput now includes `confidence` (default 1.0), so this type alias
 *  exists for backward compat with callers that pass the old shape. */
type FindingWithConfidence = FindingInput;

/**
 * Compute composite security score from findings.
 *
 * Algorithm:
 * - Start at 100
 * - Subtract weighted penalties per finding, scaled by confidence when available
 *   (confidence 0.95 → full penalty, confidence 0.50 → half penalty)
 * - Each category (code, deps, config, description, behavior) starts at 100
 *   and is reduced independently
 * - Lethal trifecta (F1) caps total score at 40
 * - Score never goes below 0 or above 100
 */
export function computeScore(
  findings: FindingInput[] | FindingWithConfidence[],
  ruleCategories: Record<string, string>,
  coverage?: AnalysisCoverageInput,
  // Phase 0, chunk 0.2: optional map of ruleId → engine_v2 flag. When any
  // rule is flagged true, total_score_v2 is populated alongside total_score.
  // Omit or pass an empty object to preserve pre-0.2 behaviour.
  ruleEngineV2Flags?: Record<string, boolean>,
): ScoreResult {
  // Legacy sub-scores (5 — backward-compatible)
  const legacyScores = {
    code_score: 100,
    deps_score: 100,
    config_score: 100,
    description_score: 100,
    behavior_score: 100,
  };

  // v2 sub-scores (8 — balanced, no single bucket absorbs 141 rules)
  const v2Scores: Record<V2ScoreKey, number> = {
    code_score: 100,
    description_score: 100,
    schema_score: 100,
    ecosystem_score: 100,
    protocol_score: 100,
    adversarial_score: 100,
    compliance_score: 100,
    supply_chain_score: 100,
    infrastructure_score: 100,
  };

  const penalties: ScoreResult["penalty_breakdown"] = [];
  let totalPenalty = 0;
  let hasLethalTrifecta = false;

  // Phase 0, chunk 0.2: parallel accumulator for rules opted into engine_v2.
  // Stays at 0 when no rule is engine_v2, which maps to a null shadow score
  // after the loop (a null signal is clearer than "perfect 100").
  let totalPenaltyV2 = 0;
  let hasLethalTrifectaV2 = false;
  const techniquesV2: Record<string, string> = {};
  const v2Eligible = ruleEngineV2Flags ?? {};
  const anyV2Rule = Object.values(v2Eligible).some((v) => v === true);

  // Track OWASP coverage
  const owaspHits = new Set<string>();

  for (const finding of findings) {
    const basePenalty = SEVERITY_WEIGHTS[finding.severity] || 0;
    // Scale penalty by confidence: high-confidence findings pay full price,
    // low-confidence findings pay proportionally less.
    // Default confidence is 1.0 (full penalty) for backward compatibility.
    // Treat any non-finite confidence (NaN, Infinity) as 1.0 — `??` only
    // catches null/undefined, so a NaN slipping through would poison the
    // entire totalPenalty accumulator with NaN and break the INTEGER write.
    const rawConfidence = (finding as FindingWithConfidence).confidence ?? 1.0;
    const confidence = Number.isFinite(rawConfidence) ? rawConfidence : 1.0;
    const penalty = Math.round(basePenalty * confidence * 100) / 100;
    totalPenalty += penalty;

    penalties.push({
      rule_id: finding.rule_id,
      severity: finding.severity,
      penalty,
    });

    // Apply to legacy category sub-score (backward compat)
    const ruleCategory = ruleCategories[finding.rule_id];
    const legacyKey = (ruleCategory && CATEGORY_MAP[ruleCategory]) || "config_score";
    legacyScores[legacyKey] = Math.max(0, legacyScores[legacyKey] - penalty);

    // Apply to v2 sub-score (balanced — no config_score mega-bucket)
    const v2Key = (ruleCategory && CATEGORY_MAP_V2[ruleCategory]) || "infrastructure_score";
    v2Scores[v2Key] = Math.max(0, v2Scores[v2Key] - penalty);

    // Shadow accumulator for engine_v2 findings only.
    if (v2Eligible[finding.rule_id]) {
      totalPenaltyV2 += penalty;
      if (finding.rule_id === "F1" || finding.rule_id === "I13") {
        hasLethalTrifectaV2 = true;
      }
      // Until Phase 1.2 threads AnalysisTechnique through FindingInput, we
      // record the rule's category as the technique proxy. The attribution
      // is coarse but identifies WHICH v2 rule contributed.
      if (ruleCategory) techniquesV2[finding.rule_id] = ruleCategory;
    }

    // Track OWASP
    if (finding.owasp_category) {
      owaspHits.add(finding.owasp_category);
    }

    // Check lethal trifecta (F1 per-server, I13 cross-config)
    if (finding.rule_id === "F1" || finding.rule_id === "I13") {
      hasLethalTrifecta = true;
    }
  }

  // Final clamp: if a non-finite value somehow slipped through (NaN penalty
  // from a malformed finding, Infinity from an upstream bug), fall back to
  // 100 and log loudly rather than letting `Math.max(0, NaN) === NaN` flow
  // downstream. The DB layer rounds to INTEGER at the storage boundary;
  // scorer output keeps its full fractional precision for tests + analytics.
  const rawTotalScore = Math.max(0, Math.min(100, 100 - totalPenalty));
  let totalScore = Number.isFinite(rawTotalScore) ? rawTotalScore : 100;
  if (!Number.isFinite(rawTotalScore)) {
    logger.warn(
      { totalPenalty, findings_count: findings.length },
      "Non-finite totalScore from scorer — defaulting to 100; check for NaN confidence on a finding",
    );
  }

  // Lethal trifecta cap
  if (hasLethalTrifecta && totalScore > 40) {
    totalScore = 40;
    logger.info("Lethal trifecta detected — capping score at 40");
  }

  // Shadow v2 score — only meaningful when at least one rule is engine_v2.
  let totalScoreV2: number | null = null;
  if (anyV2Rule) {
    const rawV2 = Math.max(0, Math.min(100, 100 - totalPenaltyV2));
    totalScoreV2 = Number.isFinite(rawV2) ? rawV2 : 100;
    if (hasLethalTrifectaV2 && totalScoreV2 > 40) {
      totalScoreV2 = 40;
    }
    totalScoreV2 = Math.round(totalScoreV2);
  }

  // Build OWASP coverage map
  const owaspCoverage: Record<string, boolean> = {};
  for (const cat of OWASP_CATEGORIES) {
    owaspCoverage[cat] = !owaspHits.has(cat); // true = no findings = clean
  }

  logger.info(
    {
      totalScore,
      findings: findings.length,
      totalPenalty,
      hasLethalTrifecta,
      v2_scores: {
        schema: v2Scores.schema_score,
        ecosystem: v2Scores.ecosystem_score,
        protocol: v2Scores.protocol_score,
        adversarial: v2Scores.adversarial_score,
        compliance: v2Scores.compliance_score,
        supply_chain: v2Scores.supply_chain_score,
        infrastructure: v2Scores.infrastructure_score,
      },
    },
    "Score computed"
  );

  return {
    total_score: totalScore,
    // Legacy sub-scores
    ...legacyScores,
    // v2 sub-scores
    schema_score: v2Scores.schema_score,
    ecosystem_score: v2Scores.ecosystem_score,
    protocol_score: v2Scores.protocol_score,
    adversarial_score: v2Scores.adversarial_score,
    compliance_score: v2Scores.compliance_score,
    supply_chain_score: v2Scores.supply_chain_score,
    infrastructure_score: v2Scores.infrastructure_score,
    owasp_coverage: owaspCoverage,
    penalty_breakdown: penalties,
    total_score_v2: totalScoreV2,
    techniques_v2: techniquesV2,
    ...(coverage ? { analysis_coverage: coverage } : {}),
  };
}
