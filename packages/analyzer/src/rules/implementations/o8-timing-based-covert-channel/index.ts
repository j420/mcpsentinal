/**
 * O8 — Timing-Based Covert Channel (Rule Standard v2).
 *
 * AST detection of timing primitives (setTimeout / sleep / setInterval /
 * Retry-After / progress-interval) whose delay expression is
 * data-dependent (non-literal, non-counter). Honest-refusal gate:
 * skips entirely when the source contains no timing primitive.
 *
 * Confidence cap: 0.72 per CHARTER. Timing is a weak static signal
 * and runtime confirmation via a constant-time floor is the correct
 * mitigation; the cap preserves reviewer headroom.
 *
 * Zero regex literals; detection vocabulary in data/timing-primitives.ts.
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
import { gatherO8, type TimingSite } from "./gather.js";
import {
  stepInspectTimingCall,
  stepCheckConstantTimeFloor,
  stepTraceDataDependency,
} from "./verification.js";

const RULE_ID = "O8";
const RULE_NAME = "Timing-Based Covert Channel";
const OWASP = "MCP04-data-exfiltration" as const;
const MITRE = "AML.T0057" as const;
const CONFIDENCE_CAP = 0.72;

const REMEDIATION =
  "Never derive sleep / setTimeout / setInterval / Retry-After durations " +
  "from secret, tool-input, or caller-varying state. Use fixed rate-limit " +
  "intervals, deterministic exponential backoff (baseDelay * 2 ** retryCount), " +
  "or randomised jitter with no data-dependent term. For defence in depth, " +
  "wrap every MCP tool handler in a constant-time response floor — pad the " +
  "final await to a uniform duration before emit so the measured latency " +
  "carries no exfiltratable signal.";

const STRATEGY_PRIMITIVE = "ast-timing-primitive-catalogue";
const STRATEGY_DATA_DEP = "data-dependent-delay-expression";
const STRATEGY_RETRY = "retry-after-header-modulation";
const STRATEGY_PROGRESS = "progress-notification-timing-cross-ref";
const STRATEGY_HONEST_REFUSAL = "honest-refusal-no-timing-primitive";

const FACTOR_DATA_DEP = "timing_primitive_with_data_dependency";
const FACTOR_NO_CONSTANT = "no_constant_delay_observed";
const FACTOR_DATA_HINT = "delay_reads_data_hint_identifier";
const FACTOR_SHAPE = "timing_shape_category";

class O8Rule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  readonly edgeCaseStrategies = [
    STRATEGY_PRIMITIVE,
    STRATEGY_DATA_DEP,
    STRATEGY_RETRY,
    STRATEGY_PROGRESS,
    STRATEGY_HONEST_REFUSAL,
  ] as const;

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherO8(context);
    if (!gathered.hasTimingPrimitive) return [];
    if (gathered.sites.length === 0) return [];

    const out: RuleResult[] = [];
    const seen = new Set<string>();
    for (const site of gathered.sites) {
      const key = siteKey(site);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(this.buildFinding(site));
    }
    return out.slice(0, 10);
  }

  private buildFinding(site: TimingSite): RuleResult {
    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain: this.buildChain(site),
    };
  }

  private buildChain(site: TimingSite): EvidenceChain {
    const shapeHuman = shapeLabel(site.shape);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.delayExpression,
        rationale:
          `Timing primitive "${site.primitive}" is invoked with a ` +
          `non-constant delay expression (${site.delayExpression}). ` +
          `Whichever variable the delay reads, its value influences the ` +
          `measured response latency — exactly the channel a content-` +
          `inspection DLP / SIEM / API gateway cannot observe.`,
      })
      .propagation({
        propagation_type: "function-call",
        location: site.location,
        observed:
          `Delay argument → ${site.primitive}(...) → measurable response ` +
          `latency. ${site.delayReadsIdentifier ? `The argument reads identifier "${site.delayReadsIdentifier}".` : "The argument is a non-literal expression."}`,
      })
      .sink({
        sink_type: "network-send",
        location: site.location,
        observed:
          `${shapeHuman}: the caller measures the request→response gap and ` +
          `reconstructs the delay-encoded data.`,
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "user-data",
        exploitability: "complex",
        scenario:
          `Across N calls the caller reconstructs N bits (or N bytes) of ` +
          `secret state from the delay-encoded signal alone. No payload ` +
          `content leaves the server, so content DLP, SIEM, and API ` +
          `gateway logs are all blind. Schneier (Feb 2026) and Whisper ` +
          `Leak (arXiv Nov 2025) demonstrate >98% AUPRC recovery of ` +
          `sensitive state from latency channels in LLM serving.`,
      })
      .factor(
        FACTOR_DATA_DEP,
        0.12,
        `Delay argument is a non-literal expression ` +
          `(${STRATEGY_DATA_DEP} / ${STRATEGY_PRIMITIVE}).`,
      )
      .factor(
        FACTOR_NO_CONSTANT,
        0.08,
        `No counter identifier (retryCount / attempt / delayMs / ` +
          `RATE_LIMIT_MS / backoff) observed in the delay expression.`,
      )
      .factor(
        FACTOR_DATA_HINT,
        site.matchedDataHint ? 0.06 : 0.0,
        site.matchedDataHint
          ? `Delay reads identifier "${site.matchedDataHint}" — the name is ` +
            `a positive data-dependency hint (secret / token / data / bit / ch).`
          : `No data-dependency hint identifier observed; the weaker signal ` +
            `still warrants review because the delay is non-constant.`,
      )
      .factor(
        FACTOR_SHAPE,
        0.02,
        `Timing shape: ${site.shape} (${site.shape === "retry-after-header" ? STRATEGY_RETRY : site.shape === "progress-interval-modulation" ? STRATEGY_PROGRESS : STRATEGY_PRIMITIVE}).`,
      )
      .reference({
        id: "MITRE-ATLAS-AML-T0057",
        title: "MITRE ATLAS AML.T0057 — LLM Data Leakage",
        url: "https://atlas.mitre.org/techniques/AML.T0057",
        relevance:
          "Timing-channel exfiltration is the highest-stealth member of the " +
          "T0057 family: content inspection cannot see the bits; only a " +
          "constant-time response floor nullifies the primitive.",
      })
      .verification(stepInspectTimingCall(site))
      .verification(stepCheckConstantTimeFloor(site))
      .verification(stepTraceDataDependency(site));

    return capConfidence(builder.build(), CONFIDENCE_CAP);
  }
}

function siteKey(site: TimingSite): string {
  const loc =
    site.location.kind === "source"
      ? `${site.location.file}:${site.location.line}:${site.location.col ?? 0}`
      : site.location.kind;
  return `${site.primitive}|${site.shape}|${loc}`;
}

function shapeLabel(shape: TimingSite["shape"]): string {
  switch (shape) {
    case "set-timeout-call":
      return "setTimeout / setInterval response-latency modulation";
    case "promise-settimeout":
      return "await new Promise(r => setTimeout(r, ...))";
    case "sleep-call":
      return "await sleep(...) / time.sleep / asyncio.sleep";
    case "retry-after-header":
      return "Retry-After header modulation";
    case "progress-interval-modulation":
      return "progress-notification interval modulation";
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `O8 charter caps confidence at ${cap}. Timing is a weak static signal; ` +
      `runtime confirmation is required to prove the channel. The cap holds ` +
      `reviewer headroom for legitimate non-data delays the static walker ` +
      `misclassifies.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new O8Rule());

export { O8Rule };
