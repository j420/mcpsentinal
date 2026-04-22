/**
 * P5 — Secrets in Container Build Layers (v2)
 *
 * One finding per ARG / ENV / COPY / inline-assignment site. Confidence
 * cap 0.80 — identifier-name heuristic produces occasional false
 * positives (e.g. descriptor-style names) that operator review must
 * triage.
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
import { gatherP5, type P5Hit } from "./gather.js";
import {
  stepInspectDockerfileLine,
  stepRecordConfigPointer,
  stepCheckBuildKitMigration,
  stepCheckDockerignore,
} from "./verification.js";

const RULE_ID = "P5";
const RULE_NAME = "Secrets in Container Build Layers";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0057";
const CONFIDENCE_CAP = 0.8;

const REMEDIATION =
  "Remove credentials from Dockerfile ARG / ENV / COPY directives. Migrate to " +
  "BuildKit secret mounts: `# syntax=docker/dockerfile:1.4` at the top, then " +
  "`RUN --mount=type=secret,id=<name> <command>` where the secret is supplied " +
  "via `docker build --secret id=<name>,src=<path>`. The secret is available " +
  "to the RUN step but is NOT written to the image layer. For runtime " +
  "credentials, pass via `-e`, Docker secrets, or a mounted tmpfs — never bake " +
  "into the image. Add .env / credentials.json / id_rsa / .npmrc to .dockerignore " +
  "to prevent leaks via the build context.";

class SecretsInBuildLayersRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherP5(context);
    if (gathered.hits.length === 0) return [];
    return gathered.hits.map((hit) => this.buildFinding(hit));
  }

  private buildFinding(hit: P5Hit): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: hit.location,
        observed: hit.observed,
        rationale:
          `Dockerfile ${hit.variant.toUpperCase()} directive carries credential ` +
          `identifier "${hit.credentialName}". Build-time ARG / ENV values persist ` +
          `in the image layer history; COPY'd credential files persist in the ` +
          `image filesystem. Both are retrievable via standard Docker tooling by ` +
          `anyone with image pull access.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: hit.configLocation,
        observed:
          `Identifier bakes into the image layer during \`docker build\`. For ` +
          `ARG, the default value (or --build-arg override) is captured in the ` +
          `layer history; for ENV, the value is in both history and \`docker inspect\`; ` +
          `for COPY, the file is in the image filesystem.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: hit.configLocation,
        observed:
          `Credential "${hit.credentialName}" is retrievable via ` +
          `\`docker history --no-trunc <image>\` (for ARG / ENV) or ` +
          `\`docker save\` + \`tar -x\` (for COPY'd files).`,
      })
      .impact({
        impact_type: "credential-theft",
        scope: "connected-services",
        exploitability: "trivial",
        scenario:
          `Attacker with image pull access runs \`docker history --no-trunc ` +
          `<image>\` and extracts "${hit.credentialName}" from the layer history. ` +
          `For private registries, pull access is usually granted to the entire ` +
          `dev org; for public registries, everyone on the internet has access. ` +
          `The credential is then used for cross-service lateral movement ` +
          `(cloud IAM, npm registry auth, database reach, SSH login).`,
      })
      .factor(
        "variant",
        hit.weight * 0.1,
        `Directive variant: ${hit.variant} (weight ${hit.weight}).`,
      )
      .factor(
        "credential_name",
        0.03,
        `Matched credential identifier: ${hit.credentialName} (${hit.credentialKind}).`,
      )
      .factor(
        "buildkit_secret_nearby",
        hit.buildkitSecretNearby ? -0.05 : 0.03,
        hit.buildkitSecretNearby
          ? `Dockerfile already uses BuildKit secret mounts elsewhere — migration ` +
            `pathway is short. Slight negative confidence adjustment reflects ` +
            `operator awareness of the correct pattern.`
          : `Dockerfile does not use BuildKit secret mounts — operator is on the ` +
            `pre-BuildKit pattern throughout.`,
      )
      .reference({
        id: "CWE-538",
        title: "CWE-538 — Insertion of Sensitive Information into Externally-Accessible File or Directory",
        url: "https://cwe.mitre.org/data/definitions/538.html",
        relevance:
          "CWE-538 is the parent weakness. Dockerfile ARG defaults and ENV values " +
          "persist in externally-accessible image layer history; COPY'd .env / " +
          "credentials files persist in the image filesystem. Both are retrievable " +
          "by anyone with image pull access.",
      })
      .verification(stepInspectDockerfileLine(hit))
      .verification(stepRecordConfigPointer(hit))
      .verification(stepCheckBuildKitMigration(hit))
      .verification(stepCheckDockerignore(hit));

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
      `P5 charter caps confidence at ${cap} — identifier-name heuristics ` +
      `occasionally false-positive on descriptor-style names.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new SecretsInBuildLayersRule());

export { SecretsInBuildLayersRule };
