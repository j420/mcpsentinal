/**
 * G7 — DNS-Based Data Exfiltration Channel, Rule Standard v2.
 *
 * REPLACES the G7 definition in
 * `packages/analyzer/src/rules/implementations/secret-exfil-detector.ts`.
 *
 * Detection is a structural AST scan (see gather.ts). Emits a v2
 * RuleResult for every DNS-resolution call whose hostname argument is
 * constructed dynamically. Evidence chain:
 *
 *   - source link (source_type mapped from observed sensitive markers
 *     — environment / user-parameter / file-content fallback)
 *   - one propagation link per dynamic hop (template-embed /
 *     concatenation / identifier-ref / wrapper-call)
 *   - sink link (sink_type network-send, cve_precedent T1071.004)
 *   - mitigation link (present when a hostname allowlist primitive is
 *     observed in the enclosing function scope)
 *   - impact link (data-exfiltration → connected-services)
 *
 * Confidence factors per CHARTER:
 *   - dynamic_hostname_construction
 *   - subdomain_entropy_score (Shannon entropy on the CONSTANT portion
 *     of the template literal)
 *   - unmitigated_egress_reachability
 *
 * Zero regex literals. Zero string arrays > 5.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import {
  EvidenceChainBuilder,
  type EvidenceChain,
  type SourceLink,
} from "../../../evidence.js";
import { gatherG7, type G7Fact } from "./gather.js";
import {
  stepInspectDnsSink,
  stepInspectHostnameConstruction,
  stepCheckEncodingWrappers,
  stepInspectAllowlist,
  stepCheckDnsEgressPolicy,
} from "./verification.js";

const RULE_ID = "G7";
const RULE_NAME = "DNS-Based Data Exfiltration Channel";
const OWASP = "MCP04-data-exfiltration" as const;
const MITRE = "AML.T0057" as const;
const CONFIDENCE_CAP = 0.88;

const REMEDIATION =
  "Never construct DNS hostnames from application data, user input, or " +
  "system state. If DNS-based service discovery is genuinely required, " +
  "use a static list of known-good hostnames pinned at module scope. " +
  "If dynamic hostnames are unavoidable (e.g. a real service-discovery " +
  "CNAME lookup), gate every dns.resolve / dns.lookup behind a hostname " +
  "allowlist (isAllowedHost / validateHostname) that rejects any " +
  "hostname not in a pinned suffix list. Deploy a DNS egress control " +
  "(Cloudflare Gateway, Unbound with blocklist, AWS Route 53 Resolver " +
  "DNS Firewall) that refuses to recurse on unknown domains. Monitor " +
  "DNS query logs for high-entropy subdomain patterns.";

const SUPPRESSED_REMEDIATION =
  "A hostname allowlist primitive was detected in the enclosing scope. " +
  "Confirm the check actually runs on the dynamic hostname that flows " +
  "into the DNS sink — an allowlist call on a DIFFERENT variable does " +
  "not neutralise this flow. Also confirm the allowlist itself is " +
  "populated from a pinned source, not from runtime configuration.";

function sourceTypeFromFact(fact: G7Fact): SourceLink["source_type"] {
  // Pick the most specific classification based on the observed markers.
  const kinds = new Set(fact.sensitiveSourceMatches.map((m) => m.kind));
  if (kinds.has("credential")) return "environment";
  if (kinds.has("identity")) return "user-parameter";
  if (kinds.has("content")) return "database-content";
  return "file-content";
}

function sourceRationale(fact: G7Fact): string {
  const markers =
    fact.sensitiveSourceMatches.length === 0
      ? "no explicit sensitive-identifier markers — the dynamic portion is the hostname itself"
      : `matched markers: ${fact.sensitiveSourceMatches.map((m) => `${m.token}(${m.kind})`).join(", ")}`;
  return (
    `The data feeding the DNS subdomain is not a hardcoded constant — it flows from ` +
    `application state through ${fact.dynamicHops.length} AST hop(s). ${markers}. ` +
    `Any non-constant value that reaches a DNS QNAME becomes visible to the operator of ` +
    `the authoritative nameserver and to every recursive resolver on the query path.`
  );
}

function impactScenario(fact: G7Fact): string {
  const encSummary =
    fact.encodingWrappers.length > 0
      ? ` The hostname construction runs through ${fact.encodingWrappers.map((e) => e.name).join(", ")} — a deliberate encoding step characteristic of DNS exfil.`
      : "";
  return (
    `Sensitive data (secrets, credentials, PII, session state) is encoded into DNS ` +
    `subdomain labels and exfiltrated via DNS queries. The attacker controls the ` +
    `authoritative nameserver for the target domain and reads exfiltrated data from DNS ` +
    `query logs.${encSummary} This bypasses: (1) HTTP/HTTPS firewalls — DNS uses UDP/53, ` +
    `(2) DLP systems — DNS queries are not inspected for data content, (3) SIEM ` +
    `monitoring — DNS traffic volume makes individual queries invisible, (4) network ` +
    `segmentation — DNS recursion traverses zone boundaries. Documented as MITRE ATT&CK ` +
    `T1071.004 — used by APT34, FIN7, and commodity malware.`
  );
}

export class DNSExfiltrationRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "composite"; // structural + entropy

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherG7(context);
    if (gathered.mode !== "facts") return [];

    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: G7Fact): RuleResult {
    const allowlistSuppresses = fact.allowlist !== null;
    const severity = allowlistSuppresses ? "informational" : "critical";

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: sourceTypeFromFact(fact),
        location: fact.hostnameLocation,
        observed: fact.hostnameExpression,
        rationale: sourceRationale(fact),
      });

    for (const hop of fact.dynamicHops) {
      builder.propagation({
        propagation_type:
          hop.kind === "template-embed"
            ? "template-literal"
            : hop.kind === "concatenation"
              ? "string-concatenation"
              : hop.kind === "wrapper-call"
                ? "function-call"
                : "variable-assignment",
        location: hop.location,
        observed: hop.observed,
      });
    }

    const sinkName =
      "name" in fact.sink
        ? (fact.sink as { name: string }).name
        : (fact.sink as { token: string }).token;

    builder
      .sink({
        sink_type: "network-send",
        location: fact.sinkLocation,
        observed: `${sinkName}: ${fact.sinkObserved.slice(0, 80)}`,
        cve_precedent: "MITRE-ATT&CK-T1071.004",
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: allowlistSuppresses,
        location: fact.allowlistLocation ?? fact.sinkLocation,
        detail: allowlistSuppresses
          ? `Hostname allowlist primitive \`${fact.allowlist?.name}\` observed in the enclosing function scope — ${fact.allowlist?.description}. Severity dropped to informational pending reviewer confirmation that the allowlist truly covers the dynamic hostname that reaches the DNS sink.`
          : "No hostname allowlist (isAllowedHost / validateHostname / ALLOWED_HOSTS.includes) observed in the enclosing function scope — the dynamic hostname reaches the DNS sink with no validation.",
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "connected-services",
        exploitability: fact.dynamicHops.length <= 1 ? "trivial" : "moderate",
        scenario: impactScenario(fact),
      })
      .factor(
        "dynamic_hostname_construction",
        0.12,
        `Hostname is constructed dynamically via ${fact.dynamicHops.length} hop(s) ` +
          `(${fact.dynamicHops.map((h) => h.kind).join(" → ")}). A static hostname call would ` +
          `have been skipped by the gather step.`,
      )
      .factor(
        "subdomain_entropy_score",
        entropyFactorAdjustment(fact),
        entropyFactorRationale(fact),
      )
      .factor(
        "unmitigated_egress_reachability",
        allowlistSuppresses ? -0.2 : 0.08,
        allowlistSuppresses
          ? `Hostname allowlist primitive observed — egress reachability constrained.`
          : `No in-source allowlist — dynamic hostname reaches DNS resolver unfiltered. ` +
            `A reviewer must confirm whether deployment-level DNS egress controls compensate.`,
      )
      .factor(
        "sink_classification",
        fact.sinkKind === "canonical" ? 0.03 : 0.0,
        fact.sinkKind === "canonical"
          ? `Canonical DNS sink: ${(fact.sink as { name: string }).name}.`
          : `Wrapper-by-name heuristic match: the callee name contains a DNS / resolve / lookup ` +
            `token. Confidence NOT adjusted up — the reviewer must confirm the wrapper truly ` +
            `issues a DNS query.`,
      )
      .reference({
        id: "MITRE-ATT&CK-T1071.004",
        title: "Application Layer Protocol: DNS",
        url: "https://attack.mitre.org/techniques/T1071/004/",
        year: 2024,
        relevance:
          "MITRE ATT&CK T1071.004 documents DNS as a command-and-control and data-exfiltration " +
          "channel. Attackers encode data in DNS queries to bypass network security controls. " +
          "Real-world usage by APT groups including APT34 (OilRig) and FIN7.",
      })
      .verification(stepInspectDnsSink(fact))
      .verification(stepInspectHostnameConstruction(fact))
      .verification(stepCheckEncodingWrappers(fact))
      .verification(stepInspectAllowlist(fact))
      .verification(stepCheckDnsEgressPolicy());

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: allowlistSuppresses ? SUPPRESSED_REMEDIATION : REMEDIATION,
      chain,
    };
  }
}

function entropyFactorAdjustment(fact: G7Fact): number {
  // The entropy measures the CONSTANT portion of the hostname template
  // (the attacker's domain suffix). A suspicious domain like
  // "attacker.com" has entropy ~3.4 bits/char; a legitimate one like
  // "example.com" is similar. We don't use this value to suppress the
  // finding — instead, we reward encoding-wrapper presence in the
  // dynamic portion because the runtime entropy cannot be measured
  // statically.
  if (fact.encodingWrappers.length >= 2) return 0.06;
  if (fact.encodingWrappers.length === 1) return 0.04;
  if (fact.sensitiveSourceMatches.length >= 1) return 0.02;
  return 0;
}

function entropyFactorRationale(fact: G7Fact): string {
  const parts: string[] = [];
  if (fact.constantHostnameText.length > 0) {
    parts.push(
      `Shannon entropy of the constant hostname portion ("${fact.constantHostnameText.slice(0, 60)}") = ` +
        `${fact.constantHostnameEntropy.toFixed(2)} bits/char.`,
    );
  }
  if (fact.encodingWrappers.length > 0) {
    const encs = fact.encodingWrappers.map((e) => `${e.name} (~${e.bitsPerChar} bits/char)`).join(", ");
    parts.push(`Encoding wrappers on the dynamic portion: ${encs} — deliberate high-entropy subdomain preparation.`);
  } else {
    parts.push(
      "No encoding wrapper observed on the dynamic portion — the subdomain carries raw " +
        "application data. Runtime entropy cannot be estimated statically.",
    );
  }
  if (fact.sensitiveSourceMatches.length > 0) {
    parts.push(
      `Sensitive-source markers in the hop chain: ${fact.sensitiveSourceMatches.map((m) => m.token).join(", ")}.`,
    );
  }
  return parts.join(" ");
}

function capConfidence(chain: EvidenceChain, cap: number): void {
  if (chain.confidence <= cap) return;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `G7 charter caps confidence at ${cap} — deployment-level DNS egress filters, ` +
      `hostname allowlists populated from sources outside the scanned file, and ` +
      `runtime entropy estimation are not observable at source-file scope; a ` +
      `maximum-confidence claim would overstate the static evidence.`,
  });
  chain.confidence = cap;
}

registerTypedRuleV2(new DNSExfiltrationRule());
