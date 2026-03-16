/**
 * Output scanner — runs the analysis engine over tool outputs.
 *
 * This is how we detect J5-style "tool output poisoning" at runtime:
 * the static rule flags CODE PATTERNS that produce injected outputs,
 * but the dynamic scanner catches the ACTUAL injected content in responses.
 *
 * The output is treated as a synthetic "tool description" so all
 * description-analysis rules (A1-A9, G1-G7) can fire against it.
 */
import { AnalysisEngine, type AnalysisContext } from "@mcp-sentinel/analyzer";
import { loadRules } from "@mcp-sentinel/analyzer";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_RULES_DIR = resolve(__dirname, "../../../rules");

export interface OutputFinding {
  rule_id: string;
  severity: string;
  evidence: string;
}

let _engine: AnalysisEngine | null = null;

function getEngine(): AnalysisEngine {
  if (!_engine) {
    const rules = loadRules(DEFAULT_RULES_DIR);
    // Only use description-analysis and adversarial-ai rules for output scanning
    // — code-analysis rules are meaningless against tool outputs
    const outputRules = rules.filter((r) =>
      ["description-analysis", "adversarial-ai", "threat-intelligence"].includes(r.category)
    );
    _engine = new AnalysisEngine(outputRules);
  }
  return _engine;
}

/**
 * Scan a raw tool output string for injection payloads.
 * Returns findings if any description-analysis/adversarial rules fire.
 */
export function scanToolOutput(
  toolName: string,
  rawOutput: string,
  serverId: string
): OutputFinding[] {
  if (!rawOutput || rawOutput.trim().length === 0) return [];

  // Inject the output as a fake tool description so the engine can scan it
  const syntheticCtx: AnalysisContext = {
    server: { id: serverId, name: "dynamic-scan", description: null, github_url: null },
    tools: [
      {
        name: toolName,
        description: rawOutput.slice(0, 10_000), // cap at 10k chars
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };

  const engine = getEngine();
  const findings = engine.analyze(syntheticCtx);

  return findings.map((f) => ({
    rule_id: f.rule_id,
    severity: f.severity,
    evidence: f.evidence,
  }));
}

/**
 * Check if a canary token appears in the output.
 * Used to detect reflection of injection payloads.
 */
export function detectReflection(output: string, canaryToken: string): boolean {
  return output.includes(canaryToken);
}

/**
 * Aggregate risk level from output findings.
 */
export function assessOutputRisk(
  findings: OutputFinding[]
): "none" | "low" | "medium" | "high" | "critical" {
  if (findings.length === 0) return "none";

  const hasCritical = findings.some((f) => f.severity === "critical");
  const hasHigh = findings.some((f) => f.severity === "high");
  const hasMedium = findings.some((f) => f.severity === "medium");

  if (hasCritical) return "critical";
  if (hasHigh) return "high";
  if (hasMedium) return "medium";
  return "low";
}
