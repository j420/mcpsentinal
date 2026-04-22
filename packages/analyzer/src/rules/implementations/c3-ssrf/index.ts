/**
 * C3 — Server-Side Request Forgery (Taint-Aware), Rule Standard v2.
 *
 * REPLACES the C3 definition in
 * `packages/analyzer/src/rules/implementations/code-remaining-detector.ts`.
 *
 * Uses the shared taint-rule-kit. Zero regex literals. Zero string-literal
 * arrays > 5 in this file. All configuration data lives in
 * `./data/config.ts` (under the guard-skipped `data/` directory).
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
  buildTaintChain,
  capConfidence,
  type TaintChainDescriptor,
  type TaintFact,
} from "../_shared/taint-rule-kit/index.js";
import { gatherC3 } from "./gather.js";
import {
  stepInspectSsrfSource,
  stepInspectSsrfSink,
  stepTraceSsrfPath,
  stepInspectSsrfSanitiser,
} from "./verification.js";

const RULE_ID = "C3";
const RULE_NAME = "Server-Side Request Forgery (Taint-Aware)";
const OWASP = "MCP04-data-exfiltration" as const;
const MITRE = "AML.T0057" as const;
const CONFIDENCE_CAP = 0.92;

const REMEDIATION =
  "Never pass user-controlled URL components directly to HTTP libraries. " +
  "Validate the host against a strict allowlist BEFORE issuing the request: " +
  "`const u = new URL(userUrl); if (!ALLOWED_HOSTS.has(u.hostname)) throw new Error('host not allowed');`. " +
  "After the host check, resolve DNS once and pin the resolved IP for the " +
  "request — bare hostname checks are defeated by DNS rebinding. Reject any " +
  "scheme other than `https:` (file:, data:, gopher:, dict:, ftp: are NOT " +
  "valid for tool fetch). Reject literal IPs in the private/loopback/link- " +
  "local ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, " +
  "169.254.0.0/16, ::1, fc00::/7, fe80::/10) AND their decimal/octal/hex " +
  "encodings (http://2852039166/, http://0xa9fea9fe/). Disable HTTP " +
  "redirect following — or follow only to hosts that pass the same allowlist. " +
  "Prefer a charter-audited helper (`safeFetch`, `assertPublicHost`, " +
  "`pinResolvedIp`, `isAllowedUrl`, `ssrfFilter`) over ad-hoc string " +
  "manipulation.";

const SANITIZED_REMEDIATION =
  "A sanitiser was detected on the taint path; nonetheless, confirm the " +
  "binding really resolves to a charter-audited allowlist + DNS-pin " +
  "(safeFetch / pinResolvedIp / assertPublicHost / isAllowedUrl). Bare " +
  "`new URL(userInput)` does NOT prove the request will not reach an " +
  "internal IP — the WHATWG URL parser does not check IP ranges and " +
  "the underlying HTTP client re-resolves DNS at request time. The " +
  "finding remains at informational until a reviewer confirms the " +
  "allowlist + pin are real.";

const DESCRIPTOR: TaintChainDescriptor = {
  ruleId: RULE_ID,
  sourceType: "user-parameter",
  sinkType: "network-send",
  cvePrecedent: "CWE-918",
  impactType: "data-exfiltration",
  impactScope: "connected-services",
  sourceRationale: (fact) =>
    `Untrusted ${fact.sourceCategory} source — the expression reads from an ` +
    `external input surface (HTTP body/query/params, MCP tool parameter, ` +
    `process.env, request.form). Nothing on the path validates the host, ` +
    `pins DNS, or restricts the scheme, so every URL the attacker supplies ` +
    `survives into the outbound HTTP call.`,
  impactScenario: (fact) =>
    `Attacker crafts a URL pointing at the cloud instance metadata service ` +
    `(\`http://169.254.169.254/latest/meta-data/iam/security-credentials/\` on ` +
    `AWS, \`http://metadata.google.internal/...\` on GCP) in the ` +
    `${fact.sourceCategory} source. The payload propagates through ` +
    `${fact.path.length} hop(s) to the HTTP sink, where the MCP server ` +
    `host's HTTP stack issues the request from inside the cloud network. ` +
    `Result: short-lived IAM credentials returned in the response body, ` +
    `usable for full-account takeover until they expire (typically 1–6 ` +
    `hours). Secondary scenarios: internal-service access (Kubernetes API, ` +
    `Redis, internal admin endpoints), DNS-based exfiltration via gopher:// ` +
    `or HTTP libraries that resolve attacker-controlled hostnames, and ` +
    `scheme smuggling (file:///etc/passwd) on libraries that honour ` +
    `non-http schemes.`,
  threatReference: {
    id: "CWE-918",
    title: "CWE-918 Server-Side Request Forgery (SSRF)",
    url: "https://cwe.mitre.org/data/definitions/918.html",
    relevance:
      "User-controlled URL components in outbound HTTP requests match the " +
      "canonical SSRF pattern. In MCP deployments — almost always cloud or " +
      "corporate-internal — the MCP host is exactly the trusted hop the " +
      "attacker needs to reach IMDS, internal admin APIs, and private " +
      "service meshes.",
  },
  unmitigatedDetail:
    "No charter-audited allowlist (isAllowedUrl / assertPublicHost / " +
    "pinResolvedIp / safeFetch / ssrfFilter) found on the taint path. The " +
    "source value reaches the HTTP call with its host, scheme, and path " +
    "intact — every encoding (decimal IP, octal IP, IPv6-mapped IPv4, " +
    "DNS-rebinding hostname) survives.",
  mitigatedCharterKnownDetail: (name) =>
    `Sanitiser \`${name}\` is on the C3 charter-audited list of SSRF ` +
    `helpers. Severity drops to informational but the finding remains so a ` +
    `reviewer can confirm the binding really resolves to an allowlist + ` +
    `DNS-pin and not a string-level lookalike.`,
  mitigatedCharterUnknownDetail: (name) =>
    `Sanitiser \`${name}\` was found on the taint path but is NOT on the ` +
    `C3 charter list. \`URL\` / \`URL.parse\` / \`new URL()\` / generic ` +
    `\`validate\` are reported as sanitisers by the underlying analyser, ` +
    `but none of them check the resolved IP against private ranges or ` +
    `defeat DNS rebinding — a reviewer must audit the calling code for a ` +
    `subsequent allowlist + DNS-pin.`,
};

export class SsrfRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC3(context);
    if (gathered.mode !== "facts") return [];
    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: TaintFact): RuleResult {
    const builder = buildTaintChain(fact, DESCRIPTOR);

    builder.verification(stepInspectSsrfSource(fact));
    builder.verification(stepInspectSsrfSink(fact));
    builder.verification(stepTraceSsrfPath(fact));
    const sanitiserStep = stepInspectSsrfSanitiser(fact);
    if (sanitiserStep) builder.verification(sanitiserStep);

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP, RULE_ID);

    return {
      rule_id: RULE_ID,
      severity: fact.sanitiser ? "informational" : "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: fact.sanitiser ? SANITIZED_REMEDIATION : REMEDIATION,
      chain,
    };
  }
}

registerTypedRuleV2(new SsrfRule());
