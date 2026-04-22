/**
 * L3 — Dockerfile Base Image Supply Chain Risk (v2)
 *
 * Orchestrator. Consumes the L3 gatherer's facts (one per unsafe FROM
 * instruction) and turns each fact into a v2-compliant EvidenceChain with:
 *
 *   - source link at the FROM line (source-kind Location);
 *   - propagation link for the implicit registry-pull-at-build-time step;
 *   - sink link at the config-kind Location (Dockerfile json pointer);
 *   - mitigation link declaring whether ANY digest pin exists in-file;
 *   - impact link describing the supply-chain compromise scenario;
 *   - four verification steps walking an auditor from FROM line to
 *     registry policy check.
 *
 * Confidence is capped at 0.85 per CHARTER (room for registry-side DCT /
 * image-signing policy the analyzer cannot see).
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
import { gatherL3, type L3Fact } from "./gather.js";
import {
  stepInspectFromInstruction,
  stepCheckConfigTarget,
  stepInspectMitigation,
  stepCheckRegistryPolicy,
} from "./verification.js";

const RULE_ID = "L3";
const RULE_NAME = "Dockerfile Base Image Supply Chain Risk";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0017";
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Pin base images to SHA256 digests (FROM image@sha256:abc123…). For multi-stage " +
  "builds, pin EVERY stage — a compromised builder stage contaminates COPY --from= " +
  "outputs. Use Docker Content Trust or a registry image-signing policy (Harbor / " +
  "ECR / Quay) as a compensating control. Never use ARG default values for FROM " +
  "references without pinning the default to a digest.";

class DockerfileBaseImageRiskRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherL3(context);
    if (gathered.facts.length === 0) return [];

    return gathered.facts.map((fact) => this.buildFinding(fact));
  }

  private buildFinding(fact: L3Fact): RuleResult {
    const observedPattern =
      fact.problem.kind === "mutable-tag"
        ? `mutable keyword "${fact.problem.matchedKeyword}" in tag "${fact.from.tag ?? ""}"`
        : fact.problem.kind === "no-tag"
          ? `no tag — implicit :latest`
          : `ARG-referenced base image`;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: fact.location,
        observed: fact.from.raw,
        rationale:
          `${fact.problem.detail} An unpinned base image can be silently ` +
          `substituted at registry pull time — the exact attack model behind ` +
          `NIST SP 800-190 §4.1.2 and CVE-2019-5736 runC escape weaponisation.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: fact.location,
        observed:
          `Build-time resolution of ${observedPattern} — the registry determines ` +
          `which image content is pulled into the build output.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: fact.configLocation,
        observed:
          `Every instruction following the FROM line (RUN / COPY / CMD / ENTRYPOINT) ` +
          `inherits the binaries and libraries of the unpinned image.`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: fact.hasAnyDigestInFile,
        location: fact.configLocation,
        detail: fact.hasAnyDigestInFile
          ? `Partial: ${fact.pinnedStagesInFile} of ${fact.totalStagesInFile} FROM ` +
            `instructions pin a digest. The flagged stage does not.`
          : `None of ${fact.totalStagesInFile} FROM instruction(s) in this Dockerfile ` +
            `pin a digest.`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: fact.hasAnyDigestInFile ? "complex" : "moderate",
        scenario:
          `Attacker compromises the upstream registry or force-pushes a new image ` +
          `under the existing mutable tag. The next \`docker build\` pulls the ` +
          `malicious image. Every workload built from this Dockerfile executes ` +
          `attacker-controlled code on first invocation. Weaponised with ` +
          `CVE-2019-5736-class runC container escape, the blast radius extends to ` +
          `the build host.`,
      })
      .factor(
        "unpinned_base_image",
        0.1,
        `FROM instruction at ${fact.from.file}:${fact.from.line} does not pin a digest. ` +
          `${fact.problem.detail}`,
      )
      .factor(
        "mutable_tag_detected_or_no_tag",
        fact.problem.kind === "mutable-tag" ? 0.08 : fact.problem.kind === "no-tag" ? 0.1 : 0.05,
        fact.problem.kind === "mutable-tag"
          ? `Mutable keyword "${fact.problem.matchedKeyword}" present in tag — ` +
            `tag resolves to a moving target.`
          : fact.problem.kind === "no-tag"
            ? `No tag present — Docker defaults to :latest, the canonical mutable alias.`
            : `FROM reference uses ARG substitution — build-time argument control ` +
              `enables wholesale base-image swap.`,
      )
      .factor(
        fact.hasAnyDigestInFile ? "digest_present_elsewhere_in_dockerfile" : "no_digest_anywhere_in_dockerfile",
        fact.hasAnyDigestInFile ? -0.1 : 0.05,
        fact.hasAnyDigestInFile
          ? `Sibling stage(s) pin a digest — partial mitigation. Confidence reduced.`
          : `No digest pin anywhere in this Dockerfile — full supply-chain gap.`,
      )
      .reference({
        id: "AML.T0017",
        title: "MITRE ATLAS AML.T0017 — Supply Chain Compromise",
        url: "https://atlas.mitre.org/techniques/AML.T0017",
        relevance:
          "Mutable-tag substitution is the textbook ATLAS T0017 technique for " +
          "containerised AI systems — the compromised base image propagates into " +
          "every derived container on the next build.",
      })
      .verification(stepInspectFromInstruction(fact))
      .verification(stepCheckConfigTarget(fact))
      .verification(stepInspectMitigation(fact))
      .verification(stepCheckRegistryPolicy(fact));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

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

/**
 * Clamp chain confidence to the charter-declared cap. Records the reason so
 * the cap is auditable rather than a magic number.
 */
function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `L3 charter caps confidence at ${cap} — registry-side mitigations (Docker ` +
      `Content Trust, image-signing policy at Harbor/ECR/Quay) can reject an ` +
      `unpinned pull at build time. The analyzer cannot observe those controls ` +
      `from source, so a maximum-confidence claim would overstate the evidence.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new DockerfileBaseImageRiskRule());

export { DockerfileBaseImageRiskRule };
