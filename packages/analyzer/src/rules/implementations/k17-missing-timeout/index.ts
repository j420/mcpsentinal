/**
 * K17 — Missing Timeout or Circuit Breaker (v2)
 *
 * Orchestrator. Emits one finding per HTTP call site without a timeout.
 * Zero regex. Confidence cap 0.88 (cannot observe runtime transport
 * defaults — DNS/TCP-level timeouts set by the OS or connection pool).
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherK17, type HttpCallSite, type FileEvidence, type K17Gathered } from "./gather.js";
import {
  stepInspectCall,
  stepCheckGlobalTimeout,
  stepCheckCircuitBreaker,
} from "./verification.js";

const RULE_ID = "K17";
const RULE_NAME = "Missing Timeout or Circuit Breaker";
const OWASP = "MCP07-insecure-config" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.88;

const REMEDIATION =
  "Every HTTP call must declare an explicit timeout. For fetch: pass " +
  "`signal: AbortSignal.timeout(5000)`. For axios: pass `{ timeout: 5000 }` or " +
  "set `axios.defaults.timeout = 5000` at module scope. For got: pass " +
  "`{ timeout: { request: 5000 } }` or use `got.extend({ timeout })`. For " +
  "ky/undici: set per-call timeouts. Recommended: 30s external, 5s internal, " +
  "60s for large downloads. Pair long-lived tolerant calls with a circuit " +
  "breaker (opossum, cockatiel) to shed load when the upstream is degraded.";

const REF_OWASP_ASI08 = {
  id: "OWASP-ASI08",
  title: "OWASP Agentic Security Initiative — ASI08: Denial of Service",
  url: "https://owasp.org/www-project-agentic-security-initiative/",
  relevance:
    "ASI08 names hanging HTTP calls as the primary enabler of self-inflicted " +
    "DoS in agentic systems. An MCP tool handler that awaits a call with no " +
    "timeout can hold connection pool slots indefinitely.",
} as const;

class MissingTimeoutRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK17(context);
    const findings: RuleResult[] = [];
    for (const file of gathered.perFile) {
      if (file.isTestFile) continue;
      for (const site of file.calls) {
        if (site.hasCallTimeoutOption) continue;
        if (site.hasEnclosingAbortSignal) continue;
        if (coveredByFileGlobalTimeout(site, file)) continue;
        findings.push(this.buildFinding(site, file, gathered));
      }
    }
    return findings;
  }

  private buildFinding(
    site: HttpCallSite,
    file: FileEvidence,
    gathered: K17Gathered,
  ): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.observed,
        rationale:
          `HTTP call \`${site.clientLabel}(...)\` with no observable timeout. ` +
          `The call argument list has no timeout-shaped option, the enclosing ` +
          `function/source scope declares no AbortSignal, and no file-level ` +
          `global (axios.defaults.timeout / got.extend / ky.create with ` +
          `timeout) covers this client.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: site.location,
        observed:
          `Call flows directly to the outbound request with the default ` +
          `(typically no application-level) timeout. DNS and TCP-level ` +
          `timeouts are not in scope of this rule.`,
      })
      .sink({
        sink_type: "network-send",
        location: site.location,
        observed:
          `${site.clientLabel}() on the normal control-flow path, awaitable, ` +
          `with no user-level timeout bound.`,
      })
      .mitigation({
        mitigation_type: "rate-limit",
        present: gathered.hasCircuitBreakerDep,
        location: gathered.hasCircuitBreakerDep
          ? { kind: "dependency", ecosystem: "npm", name: gathered.circuitBreakerName!, version: "unknown" }
          : { kind: "config", file: "package.json", json_pointer: "/dependencies" },
        detail: gathered.hasCircuitBreakerDep
          ? `Circuit-breaker library "${gathered.circuitBreakerName}" is in ` +
            `project dependencies. Coverage of this specific call is not ` +
            `verifiable at the static layer.`
          : `No circuit-breaker library in project dependencies.`,
      })
      .impact({
        impact_type: "denial-of-service",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          `An unresponsive upstream server causes ${site.clientLabel}() to ` +
          `hang indefinitely. In a Node.js MCP server process the call consumes ` +
          `a socket from the pool (~6 per host on HTTP/1.1), holds the request/` +
          `response buffers, and never returns to the tool handler. With N ` +
          `concurrent MCP tool calls, the pool saturates and legitimate calls ` +
          `block. EU AI Act Art.15 (robustness) and OWASP ASI08 both require ` +
          `the system to shed load rather than collapse under it.`,
      });

    builder.factor(
      "ast_http_call_without_timeout",
      0.10,
      `AST walker confirmed the HTTP call has no timeout option and no ` +
        `AbortSignal in the enclosing scope.`,
    );
    if (!gathered.hasCircuitBreakerDep) {
      builder.factor(
        "no_circuit_breaker_dep",
        0.04,
        `No circuit-breaker library present — load-shedding is unavailable.`,
      );
    } else {
      builder.factor(
        "circuit_breaker_dep_present",
        -0.06,
        `Circuit-breaker library in dependencies may provide timeout ` +
          `coverage at a higher level — finding retained because the static ` +
          `analyzer cannot prove this call reaches the breaker.`,
      );
    }
    if (hasAnyGlobalTimeout(file)) {
      builder.factor(
        "global_timeout_present_different_client",
        -0.03,
        `A file-level global timeout exists for a different client — the ` +
          `codebase is not wholly unaware of timeouts; this specific client ` +
          `still lacks coverage.`,
      );
    }

    builder.reference(REF_OWASP_ASI08);
    builder.verification(stepInspectCall(site));
    builder.verification(stepCheckGlobalTimeout(file, site.location));
    builder.verification(stepCheckCircuitBreaker(gathered));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "medium",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function coveredByFileGlobalTimeout(site: HttpCallSite, file: FileEvidence): boolean {
  const label = site.clientLabel.toLowerCase();
  if (label.startsWith("axios") && file.hasGlobalAxiosTimeout) return true;
  if (label.startsWith("got") && file.hasGlobalGotTimeout) return true;
  if (label.startsWith("ky") && file.hasGlobalKyTimeout) return true;
  return false;
}

function hasAnyGlobalTimeout(file: FileEvidence): boolean {
  return file.hasGlobalAxiosTimeout || file.hasGlobalGotTimeout || file.hasGlobalKyTimeout;
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K17 charter caps confidence at ${cap} — the scanner cannot observe ` +
      `OS-level TCP timeouts, connection-pool defaults, or reverse-proxy ` +
      `timeouts that may bound the call externally. A maximum-confidence ` +
      `claim would overstate what static analysis can prove.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new MissingTimeoutRule());

export { MissingTimeoutRule };
