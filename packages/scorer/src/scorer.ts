import type { FindingInput, Severity } from "@mcp-sentinel/database";
import pino from "pino";

const logger = pino({ name: "scorer" });

export interface ScoreResult {
  total_score: number;
  code_score: number;
  deps_score: number;
  config_score: number;
  description_score: number;
  behavior_score: number;
  owasp_coverage: Record<string, boolean>;
  penalty_breakdown: Array<{
    rule_id: string;
    severity: string;
    penalty: number;
  }>;
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
  "auth-analysis": "config_score",
  "protocol-surface": "config_score",
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

/**
 * Compute composite security score from findings.
 *
 * Algorithm:
 * - Start at 100
 * - Subtract weighted penalties per finding
 * - Each category (code, deps, config, description, behavior) starts at 100
 *   and is reduced independently
 * - Lethal trifecta (F1) caps total score at 40
 * - Score never goes below 0 or above 100
 */
export function computeScore(
  findings: FindingInput[],
  ruleCategories: Record<string, string>
): ScoreResult {
  const categoryScores = {
    code_score: 100,
    deps_score: 100,
    config_score: 100,
    description_score: 100,
    behavior_score: 100,
  };

  const penalties: ScoreResult["penalty_breakdown"] = [];
  let totalPenalty = 0;
  let hasLethalTrifecta = false;

  // Track OWASP coverage
  const owaspHits = new Set<string>();

  for (const finding of findings) {
    const penalty = SEVERITY_WEIGHTS[finding.severity] || 0;
    totalPenalty += penalty;

    penalties.push({
      rule_id: finding.rule_id,
      severity: finding.severity,
      penalty,
    });

    // Apply to category sub-score
    const ruleCategory = ruleCategories[finding.rule_id] || "config_score";
    const scoreKey = CATEGORY_MAP[ruleCategory] || "config_score";
    categoryScores[scoreKey] = Math.max(0, categoryScores[scoreKey] - penalty);

    // Track OWASP
    if (finding.owasp_category) {
      owaspHits.add(finding.owasp_category);
    }

    // Check lethal trifecta (F1 per-server, I13 cross-config)
    if (finding.rule_id === "F1" || finding.rule_id === "I13") {
      hasLethalTrifecta = true;
    }
  }

  let totalScore = Math.max(0, Math.min(100, 100 - totalPenalty));

  // Lethal trifecta cap
  if (hasLethalTrifecta && totalScore > 40) {
    totalScore = 40;
    logger.info("Lethal trifecta detected — capping score at 40");
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
    },
    "Score computed"
  );

  return {
    total_score: totalScore,
    ...categoryScores,
    owasp_coverage: owaspCoverage,
    penalty_breakdown: penalties,
  };
}
