/**
 * K17 — Missing Timeout or Circuit Breaker (v2: AST Structural Analysis)
 *
 * REPLACES the regex rule: /(?:fetch|axios|request|http\.get)\s*\([^)]*\)(?!.*(?:timeout|signal|AbortController|deadline))/
 *
 * Old behavior: Fires on any fetch/axios call not followed by "timeout" on the same line.
 *   False positive: fetch(url, { signal }) where signal is an AbortController defined elsewhere.
 *   False negative: got(url) or undici.request(url) — not in the pattern list.
 *
 * New behavior: Uses TypeScript AST to:
 *   1. Find all HTTP request call expressions (fetch, axios, got, undici, http.request, etc.)
 *   2. Check if timeout/signal/AbortController is configured in the SAME call or enclosing scope
 *   3. Check for module-level timeout configuration (axios.defaults.timeout, got.extend({ timeout }))
 *   4. Cross-check: is AbortController imported/created in the file?
 *
 * Why this matters for compliance:
 *   - OWASP ASI08: Denial of service — hanging requests consume resources
 *   - EU AI Act Art. 15: Robustness — AI systems must be resilient
 *   - MAESTRO L4: Infrastructure must implement timeouts/circuit breakers
 *   - CoSAI MCP-T10: Resource exhaustion prevention
 */

import ts from "typescript";
import type { AnalysisContext } from "../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../base.js";
import { EvidenceChainBuilder } from "../../evidence.js";

const RULE_ID = "K17";
const RULE_NAME = "Missing Timeout or Circuit Breaker";
const OWASP = "MCP07-insecure-config";
const REMEDIATION =
  "Add timeouts to all HTTP requests. For fetch: use AbortController with setTimeout. " +
  "For axios: set `timeout` in request config or axios.defaults.timeout. " +
  "For got: set `timeout` in options. For http.request: set `timeout` option. " +
  "Recommended: 30s for external APIs, 5s for internal services, 60s for file downloads. " +
  "Consider adding circuit breakers (e.g., opossum, cockatiel) for external dependencies.";

/** HTTP client function patterns and their timeout mechanisms */
const HTTP_CLIENTS: Array<{
  pattern: RegExp;
  name: string;
  timeoutOptions: string[];
}> = [
  {
    pattern: /\bfetch\s*\(/,
    name: "fetch",
    timeoutOptions: ["signal", "AbortController", "AbortSignal.timeout"],
  },
  {
    pattern: /\baxios\s*(?:\.\s*(?:get|post|put|delete|patch|head|options|request))?\s*\(/,
    name: "axios",
    timeoutOptions: ["timeout", "signal", "AbortController"],
  },
  {
    pattern: /\bgot\s*(?:\.\s*(?:get|post|put|delete|patch|head))?\s*\(/,
    name: "got",
    timeoutOptions: ["timeout", "signal"],
  },
  {
    pattern: /\bundici\s*\.\s*(?:request|fetch)\s*\(/,
    name: "undici",
    timeoutOptions: ["signal", "headersTimeout", "bodyTimeout"],
  },
  {
    pattern: /\bhttp[s]?\s*\.\s*(?:request|get)\s*\(/,
    name: "http",
    timeoutOptions: ["timeout", "signal"],
  },
  {
    pattern: /\brequest\s*(?:\.\s*(?:get|post|put|delete|patch))?\s*\(/,
    name: "request",
    timeoutOptions: ["timeout"],
  },
  {
    pattern: /\bsuperagent\s*(?:\.\s*(?:get|post|put|delete|patch))?\s*\(/,
    name: "superagent",
    timeoutOptions: ["timeout"],
  },
  {
    pattern: /\bky\s*(?:\.\s*(?:get|post|put|delete|patch))?\s*\(/,
    name: "ky",
    timeoutOptions: ["timeout", "signal"],
  },
];

/** Patterns indicating a global/module-level timeout configuration */
const GLOBAL_TIMEOUT_PATTERNS = [
  /axios\s*\.\s*defaults\s*\.\s*timeout\s*=/,
  /axios\s*\.\s*create\s*\(\s*\{[^}]*timeout\s*:/,
  /got\s*\.\s*extend\s*\(\s*\{[^}]*timeout\s*:/,
  /new\s+AbortController\s*\(\s*\)/,
  /AbortSignal\s*\.\s*timeout\s*\(/,
  /\.timeout\s*\(\s*\d/,                    // .timeout(5000) chained
  /opossum|cockatiel|circuit.?breaker/i,    // Circuit breaker libraries
];

class MissingTimeoutRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code) return [];
    if (/(?:__tests?__|\.(?:test|spec)\.)/.test(context.source_code)) return [];

    const source = context.source_code;
    const findings: RuleResult[] = [];

    // Check for global timeout configuration
    const hasGlobalTimeout = GLOBAL_TIMEOUT_PATTERNS.some(p => p.test(source));

    // Check for circuit breaker dependency
    const hasCircuitBreaker = context.dependencies.some(d =>
      /opossum|cockatiel|circuit.?breaker|brakes|levee/i.test(d.name),
    );

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        if (ts.isCallExpression(node)) {
          const exprText = node.expression.getText(sf);
          // Include the paren for pattern matching (patterns expect it)
          const callText = exprText + "(";

          // Match against HTTP client patterns
          const matchedClient = HTTP_CLIENTS.find(c => c.pattern.test(callText));
          if (!matchedClient) { ts.forEachChild(node, visit); return; }

          // Check if timeout is configured in this specific call
          const hasLocalTimeout = this.checkCallForTimeout(node, sf, matchedClient.timeoutOptions);
          if (hasLocalTimeout) { ts.forEachChild(node, visit); return; }

          // Check enclosing scope for AbortController/timeout setup
          const hasScopeTimeout = this.checkScopeForTimeout(node, sf);
          if (hasScopeTimeout) { ts.forEachChild(node, visit); return; }

          // Skip if global timeout covers this client
          if (hasGlobalTimeout && (matchedClient.name === "axios" || matchedClient.name === "got")) {
            ts.forEachChild(node, visit);
            return;
          }

          const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
          const lineText = source.split("\n")[line - 1] || "";

          // Skip commented lines
          if (lineText.trimStart().startsWith("//") || lineText.trimStart().startsWith("*")) {
            ts.forEachChild(node, visit);
            return;
          }

          findings.push(this.buildFinding(
            exprText,
            matchedClient.name,
            line,
            lineText.trim(),
            hasGlobalTimeout,
            hasCircuitBreaker,
          ));
        }

        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch {
      // AST parse failure — skip
    }

    return findings;
  }

  /** Check if a specific call expression has timeout configuration */
  private checkCallForTimeout(
    node: ts.CallExpression,
    sf: ts.SourceFile,
    timeoutOptions: string[],
  ): boolean {
    // Check arguments for options objects containing timeout/signal
    for (const arg of node.arguments) {
      const argText = arg.getText(sf);
      for (const opt of timeoutOptions) {
        if (argText.includes(opt)) return true;
      }
    }

    // Check for chained .timeout() or .signal()
    const parent = node.parent;
    if (parent && ts.isPropertyAccessExpression(parent)) {
      const prop = parent.name.getText(sf);
      if (prop === "timeout" || prop === "signal") return true;
    }

    return false;
  }

  /** Check enclosing scope for timeout setup (e.g., const controller = new AbortController()) */
  private checkScopeForTimeout(node: ts.Node, sf: ts.SourceFile): boolean {
    let current: ts.Node | undefined = node.parent;
    while (current) {
      if (ts.isBlock(current) || ts.isSourceFile(current)) {
        const blockText = current.getText(sf);
        // Check for AbortController setup or setTimeout that would abort
        if (/new\s+AbortController|AbortSignal\.timeout|setTimeout\s*\([^)]*abort/i.test(blockText)) {
          // Verify the controller's signal is used in the same scope
          if (/\.signal\b/.test(blockText)) return true;
        }
        break; // Only check immediate enclosing block
      }
      current = current.parent;
    }
    return false;
  }

  /** Build finding for HTTP request without timeout */
  private buildFinding(
    callText: string,
    clientName: string,
    line: number,
    lineText: string,
    hasGlobalTimeout: boolean,
    hasCircuitBreaker: boolean,
  ): RuleResult {
    const builder = new EvidenceChainBuilder();

    builder.source({
      source_type: "file-content",
      location: `line ${line}`,
      observed: lineText.slice(0, 120),
      rationale:
        `HTTP request via ${clientName}() at line ${line} has no timeout configuration. ` +
        `Without a timeout, this request could hang indefinitely if the remote server is ` +
        `unresponsive, consuming a connection slot, memory, and potentially blocking the ` +
        `event loop. In an MCP server context, this can cause the entire server to become ` +
        `unresponsive to the AI client.`,
    });

    builder.propagation({
      propagation_type: "direct-pass",
      location: `line ${line}`,
      observed:
        `${callText} — call to ${clientName} without timeout/signal/AbortController. ` +
        `Checked: (1) no timeout option in call arguments, ` +
        `(2) no AbortController in enclosing scope, ` +
        `(3) ${hasGlobalTimeout ? "global timeout exists but may not cover this client" : "no global timeout configured"}.`,
    });

    builder.sink({
      sink_type: "network-send",
      location: `line ${line}`,
      observed: `${clientName}() without timeout — potential indefinite hang`,
    });

    builder.mitigation({
      mitigation_type: "rate-limit",
      present: hasCircuitBreaker,
      location: hasCircuitBreaker ? "project dependencies" : "not found",
      detail: hasCircuitBreaker
        ? "Circuit breaker library found in dependencies — may provide timeout at the circuit level"
        : "No circuit breaker library (opossum, cockatiel) in dependencies",
    });

    builder.impact({
      impact_type: "denial-of-service",
      scope: "server-host",
      exploitability: "trivial",
      scenario:
        `An unresponsive upstream server causes ${clientName}() at line ${line} to hang ` +
        `indefinitely. In Node.js, this consumes a connection from the pool (max ~6 per host) ` +
        `and holds memory for the request/response buffers. For MCP servers: the tool handler ` +
        `never returns, the AI client times out, and the user's request fails silently. ` +
        `With concurrent requests, this escalates to full server unresponsiveness.`,
    });

    builder.factor("ast_http_call", 0.08, `HTTP request via ${clientName}() confirmed by AST`);
    builder.factor("no_timeout_in_call", 0.10, "No timeout/signal in call arguments or enclosing scope");
    if (!hasGlobalTimeout) {
      builder.factor("no_global_timeout", 0.05, "No module-level timeout configuration found");
    } else {
      builder.factor("has_global_timeout", -0.10, "Module-level timeout exists — may cover this call");
    }
    if (hasCircuitBreaker) {
      builder.factor("circuit_breaker_dep", -0.08, "Circuit breaker library in dependencies");
    }

    builder.reference({
      id: "OWASP-ASI08",
      title: "OWASP Agentic Security Initiative — ASI08: Denial of Service",
      relevance: "Agentic systems must implement timeouts to prevent resource exhaustion from hanging requests.",
    });

    builder.verification({
      step_type: "inspect-source",
      instruction:
        `Check ${clientName}() call at line ${line}. Verify no timeout is configured in: ` +
        `(1) call arguments, (2) enclosing AbortController, (3) module-level defaults.`,
      target: `source_code:${line}`,
      expected_observation: `${clientName}() call without timeout configuration`,
    });

    builder.verification({
      step_type: "check-dependency",
      instruction:
        `Check if a circuit breaker library (opossum, cockatiel) is in dependencies, or ` +
        `if a global timeout is configured (axios.defaults.timeout, got.extend({ timeout })).`,
      target: "package.json:dependencies",
      expected_observation: hasCircuitBreaker
        ? "Circuit breaker found — verify it wraps this specific call"
        : "No circuit breaker in dependencies",
    });

    return {
      rule_id: RULE_ID,
      severity: "medium",
      owasp_category: OWASP,
      mitre_technique: null,
      remediation: REMEDIATION,
      chain: builder.build(),
    };
  }
}

registerTypedRuleV2(new MissingTimeoutRule());
