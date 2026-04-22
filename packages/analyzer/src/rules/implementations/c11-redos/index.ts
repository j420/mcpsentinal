/**
 * C11 — ReDoS Catastrophic Regex Backtracking (v2).
 *
 * REPLACES the C11 definition in
 * `packages/analyzer/src/rules/implementations/code-remaining-detector.ts`.
 *
 * Pure structural AST detection with a hand-coded regex-pattern
 * analyser (NO regex literals — by design; the no-static-patterns
 * guard would reject them, and ironically a regex to detect dangerous
 * regex would itself be a ReDoS risk).
 *
 * Confidence cap: 0.85 — gap reserved for sophisticated antipatterns
 * the conservative structural analyser may miss (lookahead-driven
 * blow-ups, possessive-quantifier emulation tricks).
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
import { gatherC11, type RedosFact, type C11LeakKind } from "./gather.js";
import {
  stepInspectRegexShape,
  stepCheckBoundedInput,
  stepCheckEngineSwap,
} from "./verification.js";

const RULE_ID = "C11";
const RULE_NAME = "ReDoS — Catastrophic Regex Backtracking";
const OWASP = "MCP07-insecure-config" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Never compile a user-supplied string as a regex (`new RegExp(req.body.x)`) " +
  "without a strict allowlist on the pattern. For all user-controlled " +
  "matching, switch to a linear-time engine: `re2` / `node-re2` (Node.js), " +
  "`re2` (Python). Both refuse patterns that would require backtracking. " +
  "When the V8 / CPython default engine is unavoidable, hard-cap the input " +
  "length BEFORE the regex runs (`input.substring(0, 1024)`) AND set a " +
  "per-request CPU budget (worker thread with a kill timer, or process " +
  "isolation). Audit existing patterns with `safe-regex` / `regexploit` / " +
  "`vuln-regex-detector`. The shapes the analyser flags are the canonical " +
  "antipatterns: nested quantifiers (`(a+)+`), alternation overlap " +
  "(`(a|a)+`), polynomial blow-up (`(.*)*`).";

class RedosRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC11(context);
    if (gathered.mode !== "facts") return [];
    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: RedosFact): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: fact.location,
        observed: fact.observed,
        rationale:
          `${describeKindLong(fact.kind)} — the regex shape is vulnerable to ` +
          `catastrophic backtracking. A crafted input of moderate length ` +
          `pegs one CPU for seconds-to-minutes, stalling every concurrent ` +
          `tool invocation on the MCP server.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: fact.location,
        observed:
          `Regex compiled with no length bound and no linear-time engine. ` +
          `The regex engine evaluates user-controllable input against a ` +
          `pattern whose worst-case complexity is exponential.`,
        cve_precedent: "CWE-1333",
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: fact.mitigationPresent,
        location: fact.location,
        detail:
          fact.mitigationPresent
            ? `A mitigation marker (RE2 import or maxLength / substring / ` +
              `slice bounding) was detected in the source. Confirm it ` +
              `actually covers the input that reaches THIS regex.`
            : `No mitigation marker found anywhere in the source. The regex ` +
              `runs on unbounded input with the default backtracking engine.`,
      })
      .impact({
        impact_type: "denial-of-service",
        scope: "server-host",
        exploitability: fact.kind === "user-controlled-pattern" ? "trivial" : "moderate",
        scenario:
          `An attacker submits a crafted input that triggers the regex's ` +
          `worst-case complexity: a long run of the matching character ` +
          `followed by a single non-matching character forces the engine ` +
          `to enumerate every possible alignment. CPU time on a single ` +
          `core jumps to tens of seconds. With Node's single-threaded ` +
          `event loop, the entire MCP server stalls — every other ` +
          `concurrent tool call queues behind the offending request. ` +
          `Repeated requests amplify into a complete service outage.`,
      })
      .factor(
        "ast_regex_pattern",
        kindAdjustment(fact.kind),
        `Regex shape: ${fact.kind}. ${describeKindLong(fact.kind)}.`,
      )
      .factor(
        "regex_complexity_kind",
        fact.kind === "user-controlled-pattern" ? 0.1 : 0.05,
        fact.kind === "user-controlled-pattern"
          ? "User-controlled pattern — the static analyser cannot prove anything about a regex it cannot read."
          : "Structural antipattern in a hardcoded regex — analyser is conservative; verify with a ReDoS fuzzer.",
      )
      .factor(
        "structural_test_file_guard",
        0.02,
        "AST-shape check ruled out a vitest/jest/pytest test fixture.",
      )
      .reference({
        id: "CWE-1333",
        title: "CWE-1333 Inefficient Regular Expression Complexity",
        url: "https://cwe.mitre.org/data/definitions/1333.html",
        relevance:
          "The flagged regex shape matches the canonical CWE-1333 antipatterns: " +
          "nested quantifiers, alternation overlap, or polynomial blow-up. " +
          "Real-world precedents include the `ms`, `lodash`, and " +
          "`path-to-regexp` ReDoS CVEs (2017–2024).",
      })
      .verification(stepInspectRegexShape(fact))
      .verification(stepCheckBoundedInput(fact))
      .verification(stepCheckEngineSwap(fact));

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function kindAdjustment(kind: C11LeakKind): number {
  switch (kind) {
    case "user-controlled-pattern":
      return 0.15;
    case "polynomial-blowup":
      return 0.15;
    case "nested-quantifier":
      return 0.12;
    case "alternation-overlap":
      return 0.1;
  }
}

function describeKindLong(kind: C11LeakKind): string {
  switch (kind) {
    case "user-controlled-pattern":
      return "`new RegExp(<expr>)` with a user-controllable pattern argument";
    case "nested-quantifier":
      return "Nested quantifier — group followed by `+` whose body itself contains a `+` / `*`";
    case "alternation-overlap":
      return "Alternation overlap — group containing `|` followed by a quantifier";
    case "polynomial-blowup":
      return "Polynomial blow-up — `(.*)*` / `(.+)+` / `(.*)+` shape";
  }
}

function capConfidence(chain: EvidenceChain, cap: number): void {
  if (chain.confidence <= cap) return;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `C11 charter caps confidence at ${cap}. The remaining gap to 1.0 is ` +
      `reserved for sophisticated antipatterns the conservative structural ` +
      `analyser may miss (lookahead-driven blow-ups, possessive-quantifier ` +
      `emulation tricks).`,
  });
  chain.confidence = cap;
}

registerTypedRuleV2(new RedosRule());

export { RedosRule };
