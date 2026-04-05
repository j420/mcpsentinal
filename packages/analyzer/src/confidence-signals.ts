/**
 * Confidence Signals — Server-specific factors that make evidence chains dynamic.
 *
 * Problem: Every factory-built rule produces the same evidence chain structure
 * (source → direct-pass → sink → one factor at -0.05). computeConfidence() returns
 * ~0.65 for every code match on every server. That's not dynamic.
 *
 * Solution: Analyze the CONTEXT of each finding to produce additional confidence
 * factors that vary per server. These factors feed into EvidenceChainBuilder
 * before .build() is called, so computeConfidence() produces genuinely different
 * values based on what was actually observed.
 *
 * Five server-specific signals:
 *
 * 1. Match Specificity — how specific was the regex match?
 *    A match on `os.system(user_input)` is more specific than `os.system(data)`.
 *    Measures: variable naming, function call structure, argument patterns.
 *
 * 2. Code Location Quality — where in the code was the match?
 *    A match in a request handler is more significant than one in a utility file.
 *    Measures: handler function context, export visibility, file path signals.
 *
 * 3. Nearby Mitigation Scan — are there defenses near the finding?
 *    Scans ±20 lines for validation, sanitization, guards, error handling.
 *    This is NOT the binary isTestFile() check — it grades defense quality.
 *
 * 4. Tool Context Correlation — do the server's tools corroborate the finding?
 *    A command injection finding in code is more concerning when the server
 *    has a tool named "execute_command" than when it has "get_weather".
 *
 * 5. Exposure Surface — how exposed is this server?
 *    Network-exposed (SSE/HTTP) + no auth = higher confidence the finding matters.
 *    Local stdio with 2 tools = lower confidence it's exploitable.
 *
 * Each signal returns a ConfidenceFactor that the EvidenceChainBuilder consumes.
 * computeConfidence() sums them with the base, producing a genuinely different
 * value per server.
 */

import type { AnalysisContext } from "./engine.js";
import type { ConfidenceFactor } from "./evidence.js";

// ─── Signal 1: Match Specificity ────────────────────────────────────────────

/** Patterns indicating user-controlled input (high specificity = higher confidence) */
const USER_INPUT_PATTERNS = [
  /\b(?:req|request|ctx)\.(?:body|params|query|headers)\b/,
  /\buser[_.]?input\b/i,
  /\bargv\b/,
  /\bprocess\.env\b/,
  /\bargs\[/,
  /\binput\s*=/,
];

/** Patterns indicating static/hardcoded values (low specificity = lower confidence) */
const STATIC_VALUE_PATTERNS = [
  /['"`][^'"`]{2,}['"`]/,  // string literals
  /\b\d+\b/,               // numeric literals
  /\btrue\b|\bfalse\b/,    // boolean literals
  /\bnull\b|\bundefined\b/, // null values
];

/**
 * Assess how specific the regex match is — does it involve user-controlled input
 * or static values?
 */
export function assessMatchSpecificity(
  matchText: string,
  lineText: string,
): ConfidenceFactor {
  // Check if the match or surrounding line involves user input
  const hasUserInput = USER_INPUT_PATTERNS.some(p => p.test(lineText));
  const hasStaticOnly = !hasUserInput && STATIC_VALUE_PATTERNS.some(p => p.test(matchText));

  if (hasUserInput) {
    return {
      factor: "user_input_confirmed",
      adjustment: 0.10,
      rationale: `Match involves user-controlled input: "${lineText.trim().slice(0, 60)}"`,
    };
  }
  if (hasStaticOnly) {
    return {
      factor: "static_value_only",
      adjustment: -0.10,
      rationale: `Match appears to use static/hardcoded values, reducing injection risk`,
    };
  }
  return {
    factor: "input_source_unclear",
    adjustment: 0.0,
    rationale: "Unable to determine if input is user-controlled or static",
  };
}

// ─── Signal 2: Code Location Quality ────────────────────────────────────────

/** Patterns indicating handler/route code (high-value location) */
const HANDLER_PATTERNS = [
  /(?:async\s+)?(?:function\s+)?handle\w*/i,
  /(?:app|router|server)\.(?:get|post|put|delete|patch|use)\s*\(/,
  /export\s+(?:async\s+)?function/,
  /module\.exports/,
  /(?:req|request|ctx)\s*,\s*(?:res|response|next)/,
  /\.on\s*\(\s*['"](?:message|request|data|connection)/,
];

/** Patterns indicating low-value locations (config, setup, utility) */
const LOW_VALUE_LOCATION_PATTERNS = [
  /(?:config|setup|init|bootstrap|migrate)\s*(?:=|\()/i,
  /\/\/\s*TODO/i,
  /\/\/\s*FIXME/i,
  /(?:mock|stub|fake|dummy)/i,
];

/**
 * Assess the quality of the code location where the match was found.
 * Examines surrounding lines for handler/route context.
 */
export function assessCodeLocation(
  sourceCode: string,
  matchLine: number,
): ConfidenceFactor {
  const lines = sourceCode.split("\n");
  // Look at ±10 lines for context
  const start = Math.max(0, matchLine - 11);
  const end = Math.min(lines.length, matchLine + 10);
  const context = lines.slice(start, end).join("\n");

  const isHandler = HANDLER_PATTERNS.some(p => p.test(context));
  const isLowValue = LOW_VALUE_LOCATION_PATTERNS.some(p => p.test(context));

  if (isHandler) {
    return {
      factor: "handler_code",
      adjustment: 0.08,
      rationale: "Pattern found in request handler/route code — directly reachable from tool invocation",
    };
  }
  if (isLowValue) {
    return {
      factor: "setup_config_code",
      adjustment: -0.08,
      rationale: "Pattern found in setup/config/utility code — may not be reachable at runtime",
    };
  }
  return {
    factor: "general_code",
    adjustment: 0.0,
    rationale: "Pattern found in general application code",
  };
}

// ─── Signal 3: Nearby Mitigation Scan ───────────────────────────────────────

/** Patterns indicating input validation/sanitization */
const MITIGATION_PATTERNS: Array<{ pattern: RegExp; type: string; strength: number }> = [
  // Strong mitigations
  { pattern: /(?:escapeShell|shellescape|shell_escape|shlex\.quote)\s*\(/, type: "shell_escape", strength: -0.15 },
  { pattern: /(?:parameterized|prepared)\s*(?:query|statement)/, type: "parameterized_query", strength: -0.15 },
  { pattern: /(?:execFile|execFileSync)\s*\(/, type: "safe_exec_alternative", strength: -0.15 },
  { pattern: /(?:zod|joi|yup|superstruct|ajv|validate)\s*\./, type: "schema_validation", strength: -0.12 },
  { pattern: /(?:allowlist|whitelist|safelist)\s*[.=[]/, type: "allowlist_check", strength: -0.12 },
  { pattern: /crypto\.timingSafeEqual/, type: "timing_safe_compare", strength: -0.12 },

  // Moderate mitigations
  { pattern: /if\s*\(\s*!?\w+\.(?:includes|match|test|startsWith)\s*\(/, type: "input_check", strength: -0.08 },
  { pattern: /(?:sanitize|escape|encode|purify|clean)\s*\(/, type: "sanitization_function", strength: -0.08 },
  { pattern: /typeof\s+\w+\s*===?\s*['"]string['"]/, type: "type_check", strength: -0.05 },

  // Weak mitigations
  { pattern: /try\s*\{/, type: "error_handling", strength: -0.03 },
  { pattern: /if\s*\(\s*\w+\s*(?:===?|!==?)\s*(?:null|undefined)\s*\)/, type: "null_check", strength: -0.02 },
];

/**
 * Scan ±20 lines around the finding for mitigating code patterns.
 * Returns the strongest mitigation found, or an "absent mitigation" factor.
 */
export function scanNearbyMitigations(
  sourceCode: string,
  matchLine: number,
): ConfidenceFactor {
  const lines = sourceCode.split("\n");
  const start = Math.max(0, matchLine - 21);
  const end = Math.min(lines.length, matchLine + 20);
  const nearbyCode = lines.slice(start, end).join("\n");

  let bestMitigation: { type: string; strength: number } | null = null;

  for (const { pattern, type, strength } of MITIGATION_PATTERNS) {
    if (pattern.test(nearbyCode)) {
      if (!bestMitigation || strength < bestMitigation.strength) {
        bestMitigation = { type, strength };
      }
    }
  }

  if (bestMitigation) {
    return {
      factor: `mitigation_nearby_${bestMitigation.type}`,
      adjustment: bestMitigation.strength,
      rationale: `${bestMitigation.type} found within ±20 lines — reduces exploitability`,
    };
  }

  return {
    factor: "no_nearby_mitigation",
    adjustment: 0.08,
    rationale: "No input validation, sanitization, or security controls found within ±20 lines of the vulnerable pattern",
  };
}

// ─── Signal 4: Tool Context Correlation ─────────────────────────────────────

/** Tool name patterns that indicate high-risk capabilities */
const DANGEROUS_TOOL_PATTERNS = [
  { pattern: /exec|execute|run|shell|command|terminal|bash|invoke/i, capability: "code-execution" },
  { pattern: /delete|remove|drop|destroy|purge|wipe|truncate/i, capability: "destructive-ops" },
  { pattern: /write|create|update|modify|set|put|upload|save/i, capability: "writes-data" },
  { pattern: /read|get|fetch|list|search|query|scan|download/i, capability: "reads-data" },
  { pattern: /send|email|notify|message|webhook|post|push/i, capability: "sends-network" },
  { pattern: /auth|login|token|credential|password|key|secret|oauth/i, capability: "manages-credentials" },
  { pattern: /config|setting|env|environment|preference/i, capability: "modifies-config" },
];

/**
 * Check if the server's tool set corroborates the finding.
 * A command injection finding is more credible when the server has tools
 * that execute commands.
 */
export function assessToolCorrelation(
  ctx: AnalysisContext,
  ruleCategory: string,
): ConfidenceFactor {
  const toolNames = ctx.tools.map(t => `${t.name} ${t.description || ""}`);

  // Map rule categories to relevant capabilities
  const categoryToCapability: Record<string, string[]> = {
    "command-injection": ["code-execution"],
    "code-evaluation": ["code-execution"],
    "data-exfiltration": ["sends-network", "reads-data"],
    "privilege-escalation": ["manages-credentials", "modifies-config"],
    "logging-monitoring": ["writes-data"],
    "supply-chain": [],
    "insecure-config": ["modifies-config"],
    "identity-privilege-abuse": ["manages-credentials"],
    "human-oversight-bypass": ["destructive-ops", "code-execution"],
  };

  const relevantCapabilities = categoryToCapability[ruleCategory] ?? [];
  if (relevantCapabilities.length === 0) {
    return { factor: "tool_context_neutral", adjustment: 0.0, rationale: "Rule category does not map to specific tool capabilities" };
  }

  // Check if any tools match the relevant capabilities
  let matchCount = 0;
  for (const toolText of toolNames) {
    for (const cap of relevantCapabilities) {
      const patterns = DANGEROUS_TOOL_PATTERNS.filter(p => p.capability === cap);
      if (patterns.some(p => p.pattern.test(toolText))) {
        matchCount++;
        break;
      }
    }
  }

  if (matchCount > 0) {
    return {
      factor: "tool_capability_corroborates",
      adjustment: 0.06,
      rationale: `${matchCount} tool(s) confirm the server has capabilities related to this finding`,
    };
  }

  return {
    factor: "tool_capability_mismatch",
    adjustment: -0.06,
    rationale: "Server tools do not indicate capabilities related to this finding — possible false positive",
  };
}

// ─── Signal 5: Exposure Surface ─────────────────────────────────────────────

/**
 * Assess the server's exposure based on transport and auth configuration.
 * Network-exposed + no auth = highly exposed.
 * Local stdio = low exposure.
 */
export function assessExposureSurface(
  ctx: AnalysisContext,
): ConfidenceFactor {
  const conn = ctx.connection_metadata;
  if (!conn) {
    return {
      factor: "exposure_unknown",
      adjustment: 0.0,
      rationale: "No connection metadata available — cannot assess exposure",
    };
  }

  const isNetworkExposed = conn.transport !== "stdio";
  const hasNoAuth = !conn.auth_required;

  if (isNetworkExposed && hasNoAuth) {
    return {
      factor: "network_exposed_no_auth",
      adjustment: 0.10,
      rationale: `Server uses ${conn.transport} transport with no authentication — findings are directly exploitable by anyone with network access`,
    };
  }
  if (isNetworkExposed && conn.auth_required) {
    return {
      factor: "network_exposed_auth_required",
      adjustment: 0.03,
      rationale: `Server uses ${conn.transport} transport with authentication — reduces but does not eliminate exploitability`,
    };
  }
  // stdio = local only
  return {
    factor: "local_only_transport",
    adjustment: -0.08,
    rationale: "Server uses stdio transport (local only) — findings require local access to exploit",
  };
}

// ─── Aggregate: Apply All Signals ───────────────────────────────────────────

/** The category portion of an OWASP ID like "MCP03-command-injection" → "command-injection" */
function owaspToCategory(owasp: string): string {
  const parts = owasp.split("-");
  return parts.slice(1).join("-") || owasp;
}

export interface ConfidenceSignalOptions {
  /** The source code of the server */
  sourceCode: string | null;
  /** The line number where the match was found */
  matchLine: number;
  /** The raw matched text */
  matchText: string;
  /** The full text of the line containing the match */
  lineText: string;
  /** The analysis context (server, tools, connection) */
  context: AnalysisContext;
  /** OWASP category for this rule */
  owaspCategory: string;
}

/**
 * Compute all applicable confidence signals for a code-source finding.
 * Returns factors to add to the EvidenceChainBuilder before .build().
 */
export function computeCodeSignals(opts: ConfidenceSignalOptions): ConfidenceFactor[] {
  const factors: ConfidenceFactor[] = [];

  // Signal 1: Match specificity
  factors.push(assessMatchSpecificity(opts.matchText, opts.lineText));

  // Signal 2: Code location quality
  if (opts.sourceCode) {
    factors.push(assessCodeLocation(opts.sourceCode, opts.matchLine));
  }

  // Signal 3: Nearby mitigation scan
  if (opts.sourceCode) {
    factors.push(scanNearbyMitigations(opts.sourceCode, opts.matchLine));
  }

  // Signal 4: Tool context correlation
  const category = owaspToCategory(opts.owaspCategory);
  factors.push(assessToolCorrelation(opts.context, category));

  // Signal 5: Exposure surface
  factors.push(assessExposureSurface(opts.context));

  return factors;
}

/**
 * Compute confidence signals for a tool-metadata finding.
 * Only signals 4 (tool correlation) and 5 (exposure) apply — there's no source code.
 */
export function computeToolSignals(
  ctx: AnalysisContext,
  owaspCategory: string,
  toolName: string,
): ConfidenceFactor[] {
  const factors: ConfidenceFactor[] = [];

  // Signal 4: Tool context correlation
  const category = owaspToCategory(owaspCategory);
  factors.push(assessToolCorrelation(ctx, category));

  // Signal 5: Exposure surface
  factors.push(assessExposureSurface(ctx));

  // Tool count factor — many tools = more attack surface
  if (ctx.tools.length > 15) {
    factors.push({
      factor: "high_tool_count",
      adjustment: 0.05,
      rationale: `Server has ${ctx.tools.length} tools — large attack surface increases finding relevance`,
    });
  } else if (ctx.tools.length <= 3) {
    factors.push({
      factor: "minimal_tool_count",
      adjustment: -0.05,
      rationale: `Server has only ${ctx.tools.length} tool(s) — limited attack surface`,
    });
  }

  return factors;
}
