/**
 * P3 — Cloud Metadata Service Access (v2)
 *
 * One finding per reference (endpoint or hop-limit inflation). Confidence
 * cap 0.80 — IMDSv2 required, NetworkPolicy egress blocks, and pod-level
 * IAM federation can defeat exploitation but the analyzer cannot observe
 * them from a single source file.
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
import { gatherP3, type P3Hit } from "./gather.js";
import {
  stepInspectMetadataReference,
  stepRecordConfigPointer,
  stepCheckIMDSv2Enforcement,
  stepCheckBlockRuleAbsent,
} from "./verification.js";

const RULE_ID = "P3";
const RULE_NAME = "Cloud Metadata Service Access";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0054";
const CONFIDENCE_CAP = 0.8;

const REMEDIATION =
  "Remove direct references to cloud metadata endpoints. For AWS, use the SDK " +
  "credential provider chain (which issues IMDSv2 PUT tokens automatically) and " +
  "enforce http-tokens=required on the launch template. For GCP / Azure, use " +
  "Workload Identity / Managed Identity instead of direct IMDS access. For " +
  "Kubernetes deployments, add a NetworkPolicy egress block for 169.254.169.254/32 " +
  "and fd00:ec2::/64 at the pod network level — this blocks SSRF-driven IMDS " +
  "theft regardless of application-level hardening. Set HttpPutResponseHopLimit " +
  "to 1 on EKS node launch templates.";

class CloudMetadataAccessRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherP3(context);
    if (gathered.hits.length === 0) return [];
    return gathered.hits.map((hit) => this.buildFinding(hit));
  }

  private buildFinding(hit: P3Hit): RuleResult {
    const provider = hit.kind === "endpoint" ? hit.spec.provider : "aws";
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: hit.location,
        observed: hit.observed,
        rationale:
          hit.kind === "endpoint"
            ? hit.spec.description
            : `IMDSv2 HttpPutResponseHopLimit = ${hit.value} exposes the metadata ` +
              `service to pod-level SSRF on EKS. The safe value is 1; each increment ` +
              `multiplies the reachable network hops.`,
      })
      .sink({
        sink_type: "network-send",
        location: hit.configLocation,
        observed:
          hit.kind === "endpoint"
            ? `Reference to ${hit.spec.token} (${hit.spec.provider.toUpperCase()} IMDS) ` +
              `in an application / infrastructure file — any SSRF-style sink elsewhere ` +
              `in the codebase completes the credential-theft chain.`
            : `HttpPutResponseHopLimit = ${hit.value} — widens the IMDSv2 reach.`,
      })
      .impact({
        impact_type: "credential-theft",
        scope: "connected-services",
        exploitability: "trivial",
        scenario:
          `Attacker-controlled input reaches an HTTP fetch sink; the request is ` +
          `aimed at the metadata endpoint; the service returns IAM / MSI / service-` +
          `account credentials; the attacker uses them to enumerate the target ` +
          `cloud account (S3, Secrets Manager, KMS) exactly as in the Capital One ` +
          `2019 breach.`,
      })
      .factor(
        "endpoint_variant",
        hit.kind === "endpoint" ? hit.spec.weight * 0.1 : 0.08,
        hit.kind === "endpoint"
          ? `Endpoint: ${hit.spec.id} (${hit.spec.family}).`
          : `Variant: IMDSv2 hop-limit inflation (${hit.value}).`,
      )
      .factor(
        "provider",
        0.02,
        `Cloud provider inferred: ${provider.toUpperCase()}.`,
      )
      .factor(
        "block_context_observed",
        0,
        `No block / deny / reject token on the same line (those are exempted earlier).`,
      )
      .reference({
        id: "Capital-One-2019",
        title: "Capital One 2019 breach — SSRF → IMDS → 106M record exfiltration",
        url: "https://krebsonsecurity.com/2019/08/capital-one-data-theft-impacts-106m-people/",
        relevance:
          "The Capital One 2019 breach is the canonical SSRF-to-IMDS chain. The " +
          "attacker reached 169.254.169.254 from a WAF-exposed service and exfiltrated " +
          "the EC2 instance IAM credentials, then used them to enumerate S3 buckets " +
          "across the account. Every P3 finding is a miniature version of that " +
          "precondition.",
      })
      .verification(stepInspectMetadataReference(hit))
      .verification(stepRecordConfigPointer(hit))
      .verification(stepCheckIMDSv2Enforcement(hit))
      .verification(stepCheckBlockRuleAbsent(hit));

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

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `P3 charter caps confidence at ${cap} — IMDSv2 enforcement, NetworkPolicy ` +
      `egress blocks, and pod-level IAM federation can defeat exploitation without ` +
      `showing in this file.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new CloudMetadataAccessRule());

export { CloudMetadataAccessRule };
