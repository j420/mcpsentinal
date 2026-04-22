/**
 * A3 — Suspicious URLs in Tool Description (Rule Standard v2).
 *
 * Detects URLs pointing at shorteners, tunnels, webhook canaries, or
 * suspicious TLDs inside tool descriptions. Structural URL parsing
 * (new URL()) + typed host / TLD catalogues + Shannon entropy fallback.
 * No regex literals.
 */

import type { Severity } from "@mcp-sentinel/database";
import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import { gatherA3, toolLocation, type UrlSite } from "./gather.js";
import { stepInspectUrl, stepClassifyHost } from "./verification.js";

const RULE_ID = "A3";
const RULE_NAME = "Suspicious URLs in Description";
const OWASP = "MCP04-data-exfiltration";
const MITRE = "AML.T0057";
const CONFIDENCE_CAP = 0.90;

const REMEDIATION =
  "Remove the flagged URL from the tool description or replace it with the " +
  "canonical production endpoint. Shorteners obscure the destination; tunnels " +
  "(ngrok, serveo) indicate development artefacts that should never reach " +
  "production; webhook canary hosts are designed to capture data and have no " +
  "legitimate place in a published tool description.";

/** Base severity per category — webhook canaries rate higher than cheap TLDs. */
function severityFor(site: UrlSite): Severity {
  switch (site.category) {
    case "webhook-canary":
      return "high";
    case "tunneling-service":
    case "url-shortener":
      return "medium";
    case "suspicious-tld":
    case "high-entropy-domain":
      return "medium";
  }
}

class A3SuspiciousUrlsRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const sites = gatherA3(context);
    return sites.map((s) => this.buildFinding(s));
  }

  private buildFinding(site: UrlSite): RuleResult {
    const loc = toolLocation(site.tool_name);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: loc,
        observed: site.url.slice(0, 160),
        rationale:
          `Tool description for "${site.tool_name}" contains a URL classified as ` +
          `${site.category} (${site.description}). AI clients may follow the URL ` +
          `during tool reasoning or include it in tool-call arguments.`,
      })
      .propagation({
        propagation_type: "description-directive",
        location: loc,
        observed:
          `URL string flows from the tool description into the LLM reasoning ` +
          `context. No MCP client performs reputation filtering on URLs embedded ` +
          `in tool metadata.`,
      })
      .sink({
        sink_type: "network-send",
        location: loc,
        observed: `URL destination host "${site.host}" (${site.category}).`,
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "connected-services",
        exploitability: site.category === "webhook-canary" ? "trivial" : "moderate",
        scenario:
          `The AI may be induced to fetch the URL or echo it into a tool call, ` +
          `exfiltrating request metadata to an attacker-controlled ${site.category}. ` +
          `Webhook canary services collect inbound traffic by design; shorteners ` +
          `hide the true destination.`,
      })
      .factor(
        "suspicious_url_classification",
        0.10,
        `URL host "${site.host}" matched ${site.category} catalogue with weight ${site.weight.toFixed(2)}.`,
      );

    if (site.category === "webhook-canary") {
      builder.factor(
        "webhook_canary_host",
        0.10,
        "Webhook canary services exist specifically to capture inbound data.",
      );
    }

    builder.reference({
      id: MITRE,
      title: "MITRE ATLAS — AML.T0057 LLM Data Leakage",
      url: "https://atlas.mitre.org/techniques/AML.T0057",
      relevance:
        "URL shorteners and webhook canaries are documented low-friction " +
        "exfiltration channels for LLM-mediated data leakage.",
    });

    builder.verification(stepInspectUrl(site));
    builder.verification(stepClassifyHost(site));

    const chain = builder.build();
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "url_classification_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale: `A3 charter caps confidence at ${CONFIDENCE_CAP}.`,
      });
      chain.confidence = CONFIDENCE_CAP;
    }

    return {
      rule_id: RULE_ID,
      severity: severityFor(site),
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

registerTypedRuleV2(new A3SuspiciousUrlsRule());

export { A3SuspiciousUrlsRule };
