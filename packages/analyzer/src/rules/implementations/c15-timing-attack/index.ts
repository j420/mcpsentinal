/**
 * C15 — Timing Attack on Secret or Token Comparison (v2).
 *
 * REPLACES the C15 definition in
 * `packages/analyzer/src/rules/implementations/code-remaining-detector.ts`.
 *
 * Pure structural AST detection. Zero regex literals. Detection logic
 * lives in `./gather.ts`; configuration tables live in `./data/config.ts`.
 *
 * Confidence cap: 0.90 — gap reserved for cases where the secret has
 * been renamed via destructuring or where the comparison happens
 * inside an imported helper function the static analyser does not
 * descend into.
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
import { gatherC15, type TimingFact, type C15LeakKind } from "./gather.js";
import {
  stepInspectComparison,
  stepCheckTimingSafeImport,
  stepCheckRateLimit,
} from "./verification.js";

const RULE_ID = "C15";
const RULE_NAME = "Timing Attack on Secret or Token Comparison";
const OWASP = "MCP07-insecure-config" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.9;

const REMEDIATION =
  "Replace the comparison with a constant-time equality check. Node.js: " +
  "`crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(provided))` " +
  "AFTER asserting both buffers are the same length (timingSafeEqual " +
  "throws on length mismatch — pre-check the length to avoid leaking it " +
  "via the exception). Python: `hmac.compare_digest(secret, provided)` " +
  "with both arguments coerced to bytes. NEVER use `===` / `==` / " +
  "`startsWith` / `endsWith` / `includes` / `indexOf` to compare a " +
  "credential to a request-supplied value — every short-circuit operator " +
  "leaks length-of-match via timing. Pair the timing-safe comparison " +
  "with rate limiting and a per-IP attempt cap to slow brute-force " +
  "attempts even if a future timing leak is reintroduced.";

class TimingAttackRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC15(context);
    if (gathered.mode !== "facts") return [];
    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: TimingFact): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: fact.location,
        observed: fact.observed,
        rationale:
          `${describeKindLong(fact.kind)} between secret \`${fact.secretSide}\` ` +
          `and request-derived expression \`${fact.requestSide}\`. The ` +
          `comparison short-circuits on the first mismatched byte, leaking ` +
          `prefix-match length via timing.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: fact.location,
        observed:
          `Secret comparison performed with a non-constant-time operator. ` +
          `Each request reveals one bit of information about the secret ` +
          `(matched / not matched) and many bits about the position of the ` +
          `first mismatch.`,
        cve_precedent: "CWE-208",
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: fact.mitigationPresent,
        location: fact.location,
        detail:
          fact.mitigationPresent
            ? `A timing-safe helper (timingSafeEqual / compare_digest / ` +
              `constant_time_compare / secure_compare) was detected somewhere ` +
              `in the source. Confirm THIS comparison uses it.`
            : `No timing-safe helper anywhere in the source — every secret ` +
              `comparison in this file is vulnerable.`,
      })
      .impact({
        impact_type: "credential-theft",
        scope: "connected-services",
        exploitability: "moderate",
        scenario:
          `An attacker submits one HTTP request per byte of the secret, ` +
          `varying the byte at the position they are currently testing. The ` +
          `request whose response time is highest corresponds to the byte ` +
          `that matched (pushing the comparison further into the secret). ` +
          `With ~1000 samples per byte (statistical averaging over network ` +
          `jitter) and a 32-byte secret, the full credential is recovered ` +
          `in seconds-to-minutes over the network. Public research (Brumley ` +
          `& Boneh 2005, Project-Wycheproof 2017+) demonstrates this is ` +
          `practical against real services with millisecond-scale timing.`,
      })
      .factor(
        "ast_comparison_shape",
        kindAdjustment(fact.kind),
        `Comparison shape: ${fact.kind}. ${describeKindLong(fact.kind)}.`,
      )
      .factor(
        "secret_identifier_match",
        0.05,
        `Secret operand identifier "${fact.secretSide}" matched the C15 ` +
          `secret-name list (token / secret / key / hmac / digest / ` +
          `apiKey / password / signature / session).`,
      )
      .factor(
        "structural_test_file_guard",
        0.02,
        "AST-shape check ruled out a vitest/jest/pytest test fixture.",
      )
      .reference({
        id: "CWE-208",
        title: "CWE-208 Observable Timing Discrepancy",
        url: "https://cwe.mitre.org/data/definitions/208.html",
        relevance:
          "Standard string equality (`===` / `==`) short-circuits on the " +
          "first mismatched byte; the time-to-return leaks how many leading " +
          "bytes matched. CWE-208 is the canonical weakness; the Node.js " +
          "and Python documentation are explicit that constant-time helpers " +
          "(timingSafeEqual / compare_digest) are required for credential " +
          "comparison.",
      })
      .verification(stepInspectComparison(fact))
      .verification(stepCheckTimingSafeImport(fact))
      .verification(stepCheckRateLimit(fact));

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

function kindAdjustment(kind: C15LeakKind): number {
  switch (kind) {
    case "strict-equality":
      return 0.15;
    case "loose-equality":
      return 0.15;
    case "starts-ends-with":
      return 0.12;
    case "python-equality":
      return 0.15;
  }
}

function describeKindLong(kind: C15LeakKind): string {
  switch (kind) {
    case "strict-equality":
      return "Triple-equals comparison (`===` / `!==`)";
    case "loose-equality":
      return "Loose equality comparison (`==` / `!=`)";
    case "starts-ends-with":
      return "Short-circuit string method (.startsWith / .endsWith / .includes / .indexOf)";
    case "python-equality":
      return "Python `==` operator on byte/string values";
  }
}

function capConfidence(chain: EvidenceChain, cap: number): void {
  if (chain.confidence <= cap) return;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `C15 charter caps confidence at ${cap}. The remaining gap to 1.0 is ` +
      `reserved for cases where the secret has been renamed via destructuring ` +
      `or where the comparison happens inside an imported helper function ` +
      `the static analyser does not descend into.`,
  });
  chain.confidence = cap;
}

registerTypedRuleV2(new TimingAttackRule());

export { TimingAttackRule };
