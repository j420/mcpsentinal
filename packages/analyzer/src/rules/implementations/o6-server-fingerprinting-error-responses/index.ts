/**
 * O6 — Server Fingerprinting via Error Responses (Rule Standard v2).
 *
 * The gather step walks the AST for three response-construction
 * shapes (`res.json(...)`, `throw new Error(...)`, return-in-catch)
 * and matches fingerprint-surface identifiers against the typed
 * vocabulary in data/fingerprint-surface.ts. Each hit becomes a
 * finding whose evidence chain carries:
 *
 *   source      — the identifier that flows into the response
 *   propagation — which response shape embeds it
 *   sink        — credential-exposure at the response emitter
 *   mitigation  — sanitiser adjacency check (present or absent)
 *   impact      — CVE-2026-29787 style reconnaissance payoff
 *
 * Confidence cap: 0.82 per CHARTER. The AST surface signal is strong
 * but the "intended diagnostic behind auth" case justifies reviewer
 * headroom.
 *
 * Zero regex literals. Detection vocabulary lives in data/*.ts and
 * is loaded at module-init time by the gather step.
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
import { gatherO6, type FingerprintSurfaceSite } from "./gather.js";
import {
  stepInspectResponseConstruction,
  stepCheckSanitizerAdjacency,
  stepAuthBranchDivergence,
} from "./verification.js";

const RULE_ID = "O6";
const RULE_NAME = "Server Fingerprinting via Error Responses";
const OWASP = "MCP04-data-exfiltration" as const;
const MITRE = "AML.T0057" as const;
const CONFIDENCE_CAP = 0.82;

const REMEDIATION =
  "Never expose process, OS, runtime, database, or dependency metadata in tool " +
  "responses or error messages. Use a generic error message (\"An error occurred\") " +
  "and route diagnostic detail through a structured logger that stays server-side. " +
  "Remove or gate /health/detailed, /debug, and /metrics endpoints (the CVE-2026-" +
  "29787 pattern). When errors must cross the response boundary, pass them through " +
  "a redaction shim (pino.redact, sanitizeError, scrubError) that strips process / " +
  "os / path / dependency introspection before emit. Prefer a typed error channel " +
  "that separates diagnostic detail from the response payload.";

const STRATEGY_AST = "ast-error-response-construction";
const STRATEGY_CATALOGUE = "fingerprint-surface-catalogue";
const STRATEGY_SHARED_ANCHOR = "shared-exfil-sink-anchor";
const STRATEGY_SANITIZER = "sanitizer-adjacency-check";
const STRATEGY_AUTH_BRANCH = "auth-branch-divergence-detection";

const FACTOR_SURFACE = "fingerprint_surface_in_response";
const FACTOR_NO_SANITIZER = "no_sanitizer_adjacent";
const FACTOR_SANITIZER_PRESENT = "sanitizer_adjacent_demotes";
const FACTOR_AUTH_GATED = "auth_gated_branch_headroom";
const FACTOR_SHAPE = "response_shape_category";

class O6Rule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  readonly edgeCaseStrategies = [
    STRATEGY_AST,
    STRATEGY_CATALOGUE,
    STRATEGY_SHARED_ANCHOR,
    STRATEGY_SANITIZER,
    STRATEGY_AUTH_BRANCH,
  ] as const;

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherO6(context);
    if (!gathered.hasResponseSurface && gathered.sites.length === 0) return [];

    const findings: RuleResult[] = [];
    // Deduplicate: identical (surfaceToken, shape, line) pairs collapse.
    const seen = new Set<string>();
    for (const site of gathered.sites) {
      const key = siteKey(site);
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(this.buildFinding(site));
    }
    return findings.slice(0, 10);
  }

  private buildFinding(site: FingerprintSurfaceSite): RuleResult {
    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain: this.buildChain(site),
    };
  }

  private buildChain(site: FingerprintSurfaceSite): EvidenceChain {
    const surfaceHuman = kindLabel(site.kind);
    const mitigationLocation = site.enclosingFunctionLocation ?? site.location;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.observed,
        rationale:
          `Fingerprint-surface identifier "${site.surfaceToken}" (${surfaceHuman}) ` +
          `appears inside a response-construction node. The caller that triggers this ` +
          `response path reads server reconnaissance data directly off the wire — OS ` +
          `release, Node/Python version, DB driver, dependency versions, or filesystem ` +
          `layout. CVE-2026-29787 demonstrated exactly this pattern on mcp-memory-` +
          `service /health/detailed.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: site.location,
        observed:
          `Response shape: ${site.responseShape}. The fingerprint identifier is ` +
          `embedded into the outbound payload without a redaction step between ` +
          `the primitive and the caller.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: site.location,
        observed:
          `Caller receives ${surfaceHuman} (${site.surfaceToken}) inside the ` +
          `${site.responseShape === "response-emitter-call" ? "JSON/HTTP response body" : site.responseShape === "throw-error" ? "thrown Error payload" : "catch-block return object"}.`,
        cve_precedent: "CVE-2026-29787",
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: site.hasSanitizer,
        location: mitigationLocation,
        detail: site.hasSanitizer
          ? `Sanitiser identifier "${site.matchedSanitizer ?? "<unknown>"}" in ` +
            `enclosing scope — confirm it actually runs on the flagged branch. ` +
            `(${STRATEGY_SANITIZER})`
          : `No sanitiser / redact / scrub / mask / filter identifier in the ` +
            `enclosing function — the fingerprint surface reaches the caller ` +
            `unfiltered. (${STRATEGY_SANITIZER})`,
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          `One deliberately malformed input triggers the response path and the ` +
          `caller harvests ${surfaceHuman}. Downstream, the attacker feeds the ` +
          `leaked version string into a CVE-targeting campaign, or uses the ` +
          `connection-string / filesystem-path disclosure to mount a direct ` +
          `follow-on attack. The response body passes every content-based DLP ` +
          `because the payload is dressed as a legitimate error message.`,
      })
      .factor(
        FACTOR_SURFACE,
        0.12,
        `AST-classified fingerprint surface identifier "${site.surfaceToken}" ` +
          `(${site.kind}) inside a ${site.responseShape} node ` +
          `(${STRATEGY_AST} / ${STRATEGY_CATALOGUE}).`,
      )
      .factor(
        site.hasSanitizer ? FACTOR_SANITIZER_PRESENT : FACTOR_NO_SANITIZER,
        site.hasSanitizer ? -0.18 : 0.08,
        site.hasSanitizer
          ? `Sanitiser identifier "${site.matchedSanitizer ?? "<unknown>"}" in ` +
            `enclosing scope demotes the finding: author likely routes errors ` +
            `through a scrubbing layer, but reviewer must verify the sanitiser ` +
            `actually runs on the flagged branch.`
          : `No sanitiser identifier in the enclosing function — the fingerprint ` +
            `surface reaches the caller unredacted.`,
      )
      .factor(
        FACTOR_AUTH_GATED,
        site.authGated ? -0.04 : 0.03,
        site.authGated
          ? `Flagged branch sits inside an auth-gated predicate. The auth gate ` +
            `narrows the attacker pool (stolen session still works) and justifies ` +
            `reviewer headroom (${STRATEGY_AUTH_BRANCH}).`
          : `Flagged branch is not auth-gated — any caller that triggers the ` +
            `response path observes the fingerprint surface.`,
      )
      .factor(
        FACTOR_SHAPE,
        site.responseShape === "catch-block-return" ? 0.04 : 0.02,
        `Response construction shape: ${site.responseShape}. Catch-block returns ` +
          `are especially cheap to trigger (one malformed input).`,
      )
      .reference({
        id: "CVE-2026-29787",
        title: "mcp-memory-service /health/detailed unauthenticated info leak",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2026-29787",
        relevance:
          "CVE-2026-29787 shipped /health/detailed returning OS version, CPU " +
          "cores, memory, disk paths, database info, and environment variables — " +
          "the canonical O6 precedent in the MCP ecosystem.",
      })
      .verification(stepInspectResponseConstruction(site))
      .verification(stepCheckSanitizerAdjacency(site))
      .verification(stepAuthBranchDivergence(site));

    return capConfidence(builder.build(), CONFIDENCE_CAP);
  }
}

function siteKey(site: FingerprintSurfaceSite): string {
  const locKey =
    site.location.kind === "source"
      ? `${site.location.file}:${site.location.line}`
      : site.location.kind;
  return `${site.surfaceToken}|${site.responseShape}|${locKey}`;
}

function kindLabel(kind: FingerprintSurfaceSite["kind"]): string {
  switch (kind) {
    case "process":
      return "Node process-level runtime metadata";
    case "path":
      return "filesystem path / identity metadata";
    case "os":
      return "OS / host metadata";
    case "error-field":
      return "error-object internals";
    case "db":
      return "database connection-string surface";
    case "dependency":
      return "dependency / package manifest surface";
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `O6 charter caps confidence at ${cap}. Legitimate debug endpoints behind ` +
      `an auth gate may emit the same identifiers without being an attack; the ` +
      `cap preserves reviewer headroom for the intended-diagnostic case.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new O6Rule());

export { O6Rule };
