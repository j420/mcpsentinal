/**
 * F5 — Official Namespace Squatting (v2)
 *
 * Orchestrator. Consumes the per-vendor squat classifications produced
 * by `gather.ts` and turns them into v2 RuleResult[] with evidence
 * chains that show the server name as source, the publisher-URL
 * mismatch as propagation, the squatted vendor namespace as sink, and
 * the cross-agent-propagation impact the LLM user experiences.
 *
 * Zero regex. Namespace data lives in `./data/*.ts` as typed Records.
 *
 * Confidence cap: 0.90 per charter. A vendor-approved partner may
 * legitimately use the vendor's namespace without a matching github_url.
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
import { gatherF5, type F5Site } from "./gather.js";
import {
  stepInspectServerName,
  stepVerifyPublisher,
  stepInspectRegistryListing,
} from "./verification.js";

const RULE_ID = "F5";
const RULE_NAME = "Official Namespace Squatting";
const OWASP = "MCP02-tool-poisoning" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.9;

const REMEDIATION =
  "If you own the server and are NOT affiliated with the vendor whose namespace it " +
  "contains, rename the server to remove the vendor token. Choose a name that " +
  "makes your actual publisher identity clear. If you ARE a vendor-approved partner " +
  "and intentionally use the vendor's namespace, request inclusion in the rule's " +
  "OFFICIAL_NAMESPACES.verified_github_orgs list by publishing the server under a " +
  "vendor-sanctioned GitHub organisation. Users deciding whether to approve the " +
  "server should check the repository owner against the vendor's published list of " +
  "approved partners before granting trust.";

const REF_OWASP_MCP10 = {
  id: "OWASP-MCP10-Supply-Chain",
  title: "OWASP MCP Top 10 — MCP10 Supply Chain",
  url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  relevance:
    "MCP10 explicitly lists namespace squatting as a supply-chain compromise " +
    "vector. A server claiming an official vendor namespace without publisher " +
    "proof is a direct MCP10 indicator.",
} as const;

class OfficialNamespaceSquattingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = {};
  readonly technique: AnalysisTechnique = "similarity";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherF5(context);
    return gathered.sites.map((site) => this.buildFinding(site));
  }

  private buildFinding(site: F5Site): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: site.serverLocation,
        observed: describeObserved(site),
        rationale:
          `The MCP client surfaces the server name verbatim in its approval ` +
          `dialog, and the LLM ingests the server name alongside the tool ` +
          `descriptions. A name that implies official ${site.vendor.vendor_display} ` +
          `origin hijacks the trust users and agents extend to the real vendor — ` +
          `the exact supply-chain vector Alex Birsan demonstrated in 2021 and ` +
          `Wiz Research documented in the MCP ecosystem in 2025.`,
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: site.capabilityLocation,
        observed:
          `Publisher URL "${site.githubUrl ?? "(missing)"}" is NOT under any of ` +
          `${site.vendor.vendor_display}'s verified GitHub organisations ` +
          `(${site.vendor.verified_github_orgs.join(", ")}). The server name + ` +
          `publisher mismatch propagates misplaced trust to every downstream ` +
          `tool invocation.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: site.serverLocation,
        observed:
          `Users approve the server on the basis of the vendor-branded name, ` +
          `granting it the session-scoped trust they would extend to a genuine ` +
          `${site.vendor.vendor_display} product. All subsequent tool calls ` +
          `execute under that elevated trust.`,
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "ai-client",
        exploitability: site.classifier === "substring-containment" ? "trivial" : "moderate",
        scenario:
          `User installs "${site.serverName}" believing it is an official ` +
          `${site.vendor.vendor_display} MCP server. The LLM consumes the ` +
          `impersonator's tool descriptions, instructions, and output under the ` +
          `vendor's brand halo. Subsequent prompt injection, credential ` +
          `harvesting, or data exfiltration by the impersonator inherits the ` +
          `vendor's trust across every conversation that uses the tool.`,
      });

    addClassifierFactor(builder, site);
    addPublisherFactor(builder, site);
    builder.reference(REF_OWASP_MCP10);
    builder.verification(stepInspectServerName(site));
    builder.verification(stepVerifyPublisher(site));
    builder.verification(stepInspectRegistryListing(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

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

// ─── Factor builders ───────────────────────────────────────────────────────

function addClassifierFactor(
  builder: EvidenceChainBuilder,
  site: F5Site,
): void {
  switch (site.classifier) {
    case "substring-containment":
      builder.factor(
        "official_namespace_signal",
        0.2,
        `Server name contains the vendor token "${site.vendor.org}" verbatim ` +
          `and the repository is NOT under any of the vendor's verified GitHub ` +
          `organisations. Direct containment is the highest-confidence classifier.`,
      );
      break;
    case "levenshtein-near":
      builder.factor(
        "official_namespace_signal",
        site.distance === 1 ? 0.18 : 0.1,
        `Server name is Damerau-Levenshtein distance ${site.distance} from ` +
          `"${site.vendor.org}" (threshold ${site.vendor.max_distance}). ` +
          `Distance-${site.distance} near-misses to high-value vendor namespaces ` +
          `are a dominant supply-chain signal.`,
      );
      break;
    case "visual-confusable":
      builder.factor(
        "official_namespace_signal",
        0.15,
        `ASCII visual-confusable substitution normalises server name to ` +
          `"${site.normalizedVariant ?? "(none)"}" which matches vendor namespace ` +
          `"${site.vendor.org}". This is the "0→o"/"1→l"/"rn→m" cohort — bytes ` +
          `differ, visual rendering is identical in monospaced fonts.`,
      );
      break;
    case "unicode-confusable":
      builder.factor(
        "official_namespace_signal",
        0.17,
        `Unicode confusable normalisation of server name produces ` +
          `"${site.normalizedVariant ?? "(none)"}", which matches vendor namespace ` +
          `"${site.vendor.org}". Cyrillic/Greek homoglyphs render identically to ` +
          `Latin letters in client approval dialogs.`,
      );
      break;
  }
}

function addPublisherFactor(
  builder: EvidenceChainBuilder,
  site: F5Site,
): void {
  if (site.githubUrl === null) {
    builder.factor(
      "no_publisher_url",
      0.05,
      `Server has no github_url declared. The rule cannot rule out impersonation ` +
        `without a publisher record; the missing URL compounds the namespace signal.`,
    );
  } else {
    builder.factor(
      "publisher_url_mismatch",
      0.08,
      `Publisher URL "${site.githubUrl}" is NOT under any of ` +
        `${site.vendor.vendor_display}'s verified GitHub organisations ` +
        `(${site.vendor.verified_github_orgs.join(", ")}). Publisher mismatch + ` +
        `namespace match is the canonical squat signature.`,
    );
  }
}

function describeObserved(site: F5Site): string {
  const base = `Server name "${site.serverName}" matches ${site.vendor.vendor_display} ` +
    `namespace "${site.vendor.org}"`;
  switch (site.classifier) {
    case "substring-containment":
      return `${base} via substring containment.`;
    case "levenshtein-near":
      return `${base} via Damerau-Levenshtein distance ${site.distance}.`;
    case "visual-confusable":
      return `${base} after ASCII visual-confusable substitution (→ "${site.normalizedVariant ?? "?"}").`;
    case "unicode-confusable":
      return `${base} after Unicode confusable normalisation (→ "${site.normalizedVariant ?? "?"}").`;
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `F5 charter caps confidence at ${cap} — namespace similarity + publisher ` +
      `mismatch is strong but not definitive. Vendor-approved partners may use ` +
      `the vendor namespace without a verified_github_org match, and the rule's ` +
      `curated vendor-org list can lag behind a rename. The 0.10 gap signals ` +
      `"strong static evidence, reviewer corroborates publisher identity".`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new OfficialNamespaceSquattingRule());

// Export for tests (dynamic instantiation without relying on the global registry).
export { OfficialNamespaceSquattingRule };
