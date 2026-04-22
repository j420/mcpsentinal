/**
 * C6 — Error Leakage (v2).
 *
 * REPLACES the C6 definition in
 * `packages/analyzer/src/rules/implementations/code-remaining-detector.ts`.
 *
 * Pure structural AST detection (Phase 2.4 of Rule Standard v2). Zero
 * regex literals — all string-set lookups live in `./data/config.ts`.
 * Detection logic in `./gather.ts` walks the TypeScript compiler AST
 * for response-sink calls (res.json / res.send / res.write / res.end /
 * res.status) and classifies each argument expression against the
 * five CHARTER lethal edge cases.
 *
 * Confidence cap: 0.85 — the gap to 1.0 is reserved for env-gated
 * branches and middleware-level error sanitisers the static analyser
 * cannot resolve.
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
import { gatherC6, type ErrorLeakFact, type ErrorLeakKind } from "./gather.js";
import {
  stepInspectErrorSource,
  stepInspectResponseSink,
  stepCheckProductionGate,
} from "./verification.js";

const RULE_ID = "C6";
const RULE_NAME = "Error Message Information Leakage";
const OWASP = "MCP09-logging-monitoring" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Return generic error messages to clients (e.g. `{ error: 'Internal " +
  "server error', requestId: '<uuid>' }`). Log the full error — message, " +
  "stack, code, cause chain — server-side under a structured logger so the " +
  "operator can correlate by requestId. Use a charter-audited sanitiser " +
  "(`sanitizeError`, `formatErrorForClient`, `toSafeMessage`, `redactError`, " +
  "`publicError`) that emits an opaque envelope. Never reach for `String(err)`, " +
  "`err.toString()`, `JSON.stringify(err)`, or `{ ...err }` — all four expose " +
  "the message and (often) the stack. In Express, replace the default error " +
  "middleware with a single global handler that returns the opaque envelope. " +
  "In FastAPI, override the exception handler so it never returns " +
  "`traceback.format_exc()`. Gate any `error.stack` exposure behind " +
  "`if (process.env.NODE_ENV !== 'production')` AND set NODE_ENV explicitly " +
  "in your container / deployment manifest.";

const REMEDIATION_PRODUCTION_GATED =
  "A production gate was detected on the leak. Confirm the gate actually " +
  "evaluates to false in production deployments — Docker images and " +
  "serverless wrappers frequently forget to set NODE_ENV, which collapses " +
  "the gate to 'always true'. Even with a true gate, prefer not to ship " +
  "internal error state at all: log it server-side and return an opaque " +
  "envelope on every code path.";

class ErrorLeakageRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC6(context);
    if (gathered.mode !== "facts") return [];
    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: ErrorLeakFact): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "environment",
        location: fact.sourceLocation,
        observed: fact.sourceObserved,
        rationale:
          `Server-internal error state — ${describeKindLong(fact.kind)} — is ` +
          `passed as an argument to a response-body method. Error objects in ` +
          `Node.js / Python carry stack frames, file paths, dependency ` +
          `versions, and (for cause chains) the entire ancestor exception ` +
          `tree. None of this is intended for the caller.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: fact.sinkLocation,
        observed:
          `${fact.sinkMethod}(...) call: \`${fact.sinkObserved}\`.`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: fact.sanitised || fact.productionGated,
        location: fact.sinkLocation,
        detail: fact.sanitised
          ? `Charter-audited sanitiser \`${fact.sanitiserName}\` wraps the ` +
            `error before it reaches the sink. Severity drops to informational ` +
            `but the finding remains so a reviewer can confirm the sanitiser ` +
            `is wired in correctly.`
          : fact.productionGated
            ? `An NODE_ENV / DEBUG gate wraps the leak. The gate may collapse ` +
              `to true in production if NODE_ENV is not set explicitly — ` +
              `confirm the deployment manifest sets it.`
            : `No sanitiser, no production gate. The error reaches the ` +
              `client on every request.`,
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          `An attacker triggers an error condition (malformed input, ` +
          `unauthenticated path, broken downstream service) and reads the ` +
          `response body to harvest reconnaissance data: file paths from ` +
          `the stack trace (e.g. \`/usr/src/app/handlers/tools.js\`), ` +
          `dependency versions from frame names, host environment hints ` +
          `from cause-chain messages, and — for cases that surface ` +
          `\`process.env\` values — secrets such as DB connection strings. ` +
          `The recon data drives targeted attacks against specific library ` +
          `vulnerabilities (CVE-tagged stack frames are gold to an attacker).`,
      })
      .factor(
        "ast_match",
        0.1,
        `AST-confirmed: argument to ${fact.sinkMethod}(...) at ` +
          `${renderSource(fact.sinkLocation)} is ${describeKindLong(fact.kind)}.`,
      )
      .factor(
        "error_carrier_kind",
        kindAdjustment(fact.kind),
        `Leak shape: ${fact.kind}. ${describeKindRationale(fact.kind)}`,
      )
      .factor(
        fact.productionGated ? "production_path_unguarded" : "production_path_unguarded",
        fact.productionGated ? -0.15 : 0.05,
        fact.productionGated
          ? "Surrounding NODE_ENV / DEBUG gate downgrades the finding. " +
            "Confirm production sets the env var explicitly."
          : "No NODE_ENV / DEBUG gate around the response — the leak runs " +
            "on every request, not just in development.",
      )
      .factor(
        "structural_test_file_guard",
        0.02,
        "AST-shape check ruled out a vitest/jest/pytest test fixture.",
      )
      .reference({
        id: "CWE-209",
        title: "CWE-209 Generation of Error Message Containing Sensitive Information",
        url: "https://cwe.mitre.org/data/definitions/209.html",
        relevance:
          "Exposing stack traces, file paths, and dependency versions in HTTP " +
          "responses matches CWE-209. Attackers use the recon data to plan " +
          "targeted exploitation against specific library versions and " +
          "filesystem layouts.",
      })
      .verification(stepInspectErrorSource(fact))
      .verification(stepInspectResponseSink(fact))
      .verification(stepCheckProductionGate(fact));

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: fact.sanitised || fact.productionGated ? "informational" : "medium",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: fact.productionGated ? REMEDIATION_PRODUCTION_GATED : REMEDIATION,
      chain,
    };
  }
}

function kindAdjustment(kind: ErrorLeakKind): number {
  switch (kind) {
    case "stack-property":
      return 0.15;
    case "json-stringify-error":
      return 0.12;
    case "spread-error":
      return 0.1;
    case "python-traceback":
      return 0.15;
    case "error-identifier":
      return 0.05;
  }
}

function describeKindLong(kind: ErrorLeakKind): string {
  switch (kind) {
    case "error-identifier":
      return "a bare error binding (err / error / e / ex / exception)";
    case "stack-property":
      return "a `.stack` / `.stackTrace` property access";
    case "json-stringify-error":
      return "a `JSON.stringify(err)` call (which walks .message and .stack)";
    case "spread-error":
      return "a `...err` spread (which copies every enumerable error property)";
    case "python-traceback":
      return "a `traceback.format_exc()` / `print_exc()` call (full Python stack)";
  }
}

function describeKindRationale(kind: ErrorLeakKind): string {
  switch (kind) {
    case "error-identifier":
      return "Bare Error binding — even .toString() emits the message; serialisation walks .stack.";
    case "stack-property":
      return "Direct stack-trace access. The stack carries file paths, line numbers, and dependency versions.";
    case "json-stringify-error":
      return "JSON.stringify of an Error walks message and stack and any custom properties.";
    case "spread-error":
      return "Object spread copies every enumerable property of the error — including stack and code.";
    case "python-traceback":
      return "Python traceback formatters return the entire stack as a string, including code context.";
  }
}

function renderSource(loc: { kind: string; file?: string; line?: number; col?: number }): string {
  if (loc.kind !== "source") return loc.kind;
  return loc.col !== undefined ? `${loc.file}:${loc.line}:${loc.col}` : `${loc.file}:${loc.line}`;
}

function capConfidence(chain: EvidenceChain, cap: number): void {
  if (chain.confidence <= cap) return;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `C6 charter caps confidence at ${cap}. The remaining gap to 1.0 is ` +
      `reserved for env-gated branches and middleware-level error ` +
      `sanitisers the static analyser cannot resolve at runtime.`,
  });
  chain.confidence = cap;
}

registerTypedRuleV2(new ErrorLeakageRule());

export { ErrorLeakageRule };
