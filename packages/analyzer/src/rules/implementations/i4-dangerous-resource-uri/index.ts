/**
 * I4 — Dangerous Resource URI (Rule Standard v2).
 *
 * Replaces the I4 definition in `protocol-surface-remaining-detector.ts`.
 * Inspects every declared MCP resource URI against the shared
 * DANGEROUS_URI_SCHEMES and TRAVERSAL_MARKERS catalogues. Fires per
 * resource that matches any catalogue entry.
 *
 * Detection:
 *   1. gatherI4 walks context.resources and records scheme + traversal
 *      hits per resource.
 *   2. Each hit produces ONE finding with a source → sink → impact
 *      chain citing CVE-2025-53109 as precedent.
 *   3. Confidence capped at 0.92 per charter.
 *
 * Zero regex literals. Zero string-literal arrays > 5.
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
import type { Location } from "../../location.js";
import { gatherI4, type I4Fact } from "./gather.js";
import { I4_CONFIDENCE_CAP } from "./data/config.js";
import {
  stepInspectResourceUri,
  stepCheckRootContainment,
} from "./verification.js";

const RULE_ID = "I4";
const RULE_NAME = "Dangerous Resource URI";
const OWASP = "MCP05-privilege-escalation" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "Resource URIs must use allowlisted schemes only (https, and the MCP " +
  "transport-native tokens). Refuse file://, data:, javascript:, vbscript:, " +
  "and blob: schemes at declaration time. Reject any URI containing " +
  "traversal markers (../, %2e%2e, double-encoded or Unicode variants) " +
  "before passing the URI to the client. Cross-reference I11 for the " +
  "root-containment check; CVE-2025-53109 demonstrated that declared " +
  "roots alone are insufficient — per-URI filtering is required.";

class DangerousResourceUriRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { resources: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherI4(context);
    if (gathered.facts.length === 0) return [];

    const results: RuleResult[] = [];
    for (const fact of gathered.facts) {
      const finding = this.buildFinding(fact);
      if (finding) results.push(finding);
    }
    return results;
  }

  private buildFinding(fact: I4Fact): RuleResult | null {
    const resourceLoc: Location = {
      kind: "resource",
      uri: fact.resource_uri,
      field: "uri",
    };

    const sinkKind = deriveSinkType(fact);
    const impactType = deriveImpactType(fact);
    const scope: "server-host" | "user-data" | "connected-services" =
      fact.scheme_hit?.risk_class === "file-access" ||
      fact.traversal_hit !== null
        ? "server-host"
        : "user-data";

    const schemeRationale = fact.scheme_hit
      ? `Resource URI begins with "${fact.scheme_hit.scheme}" — catalogued as ` +
        `${fact.scheme_hit.risk_class} (${fact.scheme_hit.cwe}). ` +
        `${fact.scheme_hit.rationale}`
      : `Resource URI contains the traversal marker ` +
        `"${fact.traversal_hit?.marker ?? "<unknown>"}" — ` +
        `${fact.traversal_hit?.rationale ?? "path-traversal primitive"}.`;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: resourceLoc,
        observed: `URI: ${fact.resource_uri.slice(0, 120)}`,
        rationale: schemeRationale,
      })
      .sink({
        sink_type: sinkKind,
        location: resourceLoc,
        observed:
          `The resource URI IS the sink — clients resolving the URI execute ` +
          `the scheme or follow the traversal to arbitrary filesystem / ` +
          `network / rendering surfaces.`,
        cve_precedent: "CVE-2025-53109",
      })
      .impact({
        impact_type: impactType,
        scope,
        exploitability: "trivial",
        scenario:
          `An MCP client that resolves resource "${fact.resource_name}" ` +
          `will ${describeImpact(fact)}. The attacker controls the resource ` +
          `declaration end-to-end: scheme, path, and query — ` +
          `attack does not require any tool invocation or user interaction.`,
      })
      .factor(
        "dangerous_scheme_confirmed",
        0.1,
        fact.scheme_hit
          ? `Scheme "${fact.scheme_hit.scheme}" matches catalogue entry ` +
            `(${fact.scheme_hit.risk_class}, ${fact.scheme_hit.cwe}).`
          : `Traversal marker "${fact.traversal_hit?.marker}" matches ` +
            `catalogue entry (${fact.traversal_hit?.kind}).`,
      )
      .reference({
        id: "CVE-2025-53109",
        title: "Anthropic filesystem MCP server root-boundary bypass",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-53109",
        year: 2025,
        relevance:
          "Canonical real-world demonstration that MCP resource URI handling " +
          "without per-scheme / per-traversal filters is remotely exploitable.",
      })
      .verification(stepInspectResourceUri(fact))
      .verification(stepCheckRootContainment(fact));

    if (fact.fence_hit) {
      builder.factor(
        "false_positive_fence_triggered",
        -0.12,
        "Resource URI contains a legitimate co-occurrence token (example / " +
          "readme / localhost) — the catalogue fence applies a confidence " +
          "demotion to suppress known-benign narrow cases.",
      );
    }

    const chain = capConfidence(builder.build(), I4_CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function deriveSinkType(
  fact: I4Fact,
):
  | "file-write"
  | "network-send"
  | "code-evaluation" {
  if (fact.scheme_hit?.risk_class === "file-access") return "file-write";
  if (fact.scheme_hit?.risk_class === "xss-code") return "code-evaluation";
  if (fact.traversal_hit) return "file-write";
  return "network-send";
}

function deriveImpactType(
  fact: I4Fact,
):
  | "data-exfiltration"
  | "privilege-escalation"
  | "remote-code-execution" {
  if (fact.scheme_hit?.risk_class === "xss-code") return "remote-code-execution";
  if (fact.scheme_hit?.risk_class === "file-access") return "data-exfiltration";
  if (fact.traversal_hit) return "data-exfiltration";
  return "privilege-escalation";
}

function describeImpact(fact: I4Fact): string {
  if (fact.scheme_hit?.risk_class === "file-access")
    return "read arbitrary filesystem content in the server process's scope";
  if (fact.scheme_hit?.risk_class === "xss-code")
    return "execute the embedded script in the client's rendering context";
  if (fact.scheme_hit?.risk_class === "data-injection")
    return "render attacker-controlled content without fetching a URL";
  if (fact.traversal_hit)
    return "traverse outside the intended resource scope and read data elsewhere";
  return "resolve a URI outside its intended scope";
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale: `I4 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

// ─── Registration ─────────────────────────────────────────────────────────

registerTypedRuleV2(new DangerousResourceUriRule());

export { DangerousResourceUriRule };
