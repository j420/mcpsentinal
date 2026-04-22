/**
 * L12 — Build Artifact Tampering (Rule Standard v2).
 *
 * Orchestrator. Consumes L12Fact[] from gather.ts and emits one
 * RuleResult per fact. Each fact is a tamper verb + build-dir
 * pairing observed in a post-test lifecycle hook (manifest) or a
 * CI workflow YAML.
 *
 * Zero regex. Confidence cap 0.85 per CHARTER §"Why confidence is
 * capped at 0.85".
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
import { gatherL12, type L12Fact } from "./gather.js";
import {
  stepCheckProvenance,
  stepInspectTamperSite,
  stepReproduceModification,
} from "./verification.js";

const RULE_ID = "L12";
const RULE_NAME = "Build Artifact Tampering";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0017" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Remove file-modification verbs (sed, awk, perl, patch, cat >>, echo >>, " +
  "tee) from any post-test lifecycle hook (postbuild, prepublishOnly, prepack, " +
  "postpack) and from any CI step that runs after `npm test`. All build-output " +
  "transformations must happen DURING the build step — tsc, esbuild, rollup, " +
  "webpack, vite, babel — so the test suite validates the bytes that get " +
  "published. Enable Sigstore attestation by publishing with " +
  "`npm publish --provenance` (or publishConfig.provenance: true). For CI " +
  "pipelines, separate build and publish into different jobs, upload the built " +
  "tarball as an artifact from the build job, and have the publish job download " +
  "and `npm publish` the artifact WITHOUT further modification. SLSA Build " +
  "Level 2 requires the provenance to cover the final bytes.";

class BuildArtifactTamperingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherL12(context);
    if (gathered.isTestFile) return [];
    return gathered.facts.map((f) => this.buildFinding(f));
  }

  private buildFinding(fact: L12Fact): RuleResult {
    const isCi = fact.kind === "ci-workflow-tamper";

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: fact.location,
        observed: fact.observed,
        rationale: isCi
          ? `CI workflow step contains a tamper verb (${fact.tamperVerbs.join(", ")}) ` +
            `targeting a build-output directory (${fact.buildDirs.join(", ")}). ` +
            `When this step runs after the test job, the published tarball ` +
            `contains bytes that no test covered. The Shai-Hulud worm ` +
            `(September 2025) and CVE-2025-30066 (tj-actions/changed-files, ` +
            `March 2025) used precisely this primitive.`
          : `Publish-lifecycle hook "${fact.hookOrWorkflow}" contains a tamper ` +
            `verb (${fact.tamperVerbs.join(", ")}) modifying ` +
            `${fact.buildDirs.join(", ")}. npm guarantees this hook runs AFTER ` +
            `test and BEFORE pack — the tamper bypasses test coverage and lands ` +
            `in the published tarball.`,
      })
      .propagation({
        propagation_type: "function-call",
        location: fact.location,
        observed: isCi
          ? `CI lifecycle: test → ${fact.hookOrWorkflow} → publish (artifact fetch: ` +
            `${fact.artifactFetch ? "yes" : "no"})`
          : `npm lifecycle: test → ${fact.hookOrWorkflow} → pack → publish`,
      })
      .sink({
        sink_type: "config-modification",
        location: fact.location,
        observed: `Build output modified: ${fact.buildDirs.join(", ")}`,
        cve_precedent: "CVE-2025-30066",
      })
      .mitigation({
        mitigation_type: "auth-check",
        present: fact.provenancePresent,
        location: {
          kind: "config",
          file: "package.json",
          json_pointer: "/publishConfig/provenance",
        },
        detail: fact.provenancePresent
          ? `publishConfig.provenance: true is set — Sigstore attestation covers ` +
            `the tarball. A reviewer must still confirm the attestation reflects ` +
            `post-tamper bytes; SLSA Build Level 2 requires that.`
          : `No Sigstore provenance configured; consumers cannot cryptographically ` +
            `verify the installed bytes against the tested build output.`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "connected-services",
        exploitability: "moderate",
        scenario:
          isCi
            ? `The CI step runs after tests validate the clean build output, then ` +
              `modifies dist/ (or build/ / out/ / lib/) before the publish step. ` +
              `Every consumer installing this package receives the modified ` +
              `artifact. This is the live attack pattern from CVE-2025-30066 ` +
              `(tj-actions/changed-files, March 2025) and the September 2025 ` +
              `Shai-Hulud worm.` +
              (fact.artifactFetch
                ? ` The workflow also uses download-artifact / upload-artifact, ` +
                  `indicating inter-job artifact poisoning — the tamper target ` +
                  `is an artifact produced by a different job than the test job.`
                : "")
            : `The post-test hook modifies the published tarball contents after ` +
              `the test suite has validated them. Consumers install bytes that ` +
              `were never tested, containing whatever transformation the tamper ` +
              `command applies. Historical exemplars: CVE-2025-30066 ` +
              `(tj-actions/changed-files) and the Shai-Hulud npm worm ` +
              `(September 2025), both of which used this primitive to ship ` +
              `compromised code past passing CI.`,
      })
      .factor(
        "lifecycle_ordering_proof",
        0.15,
        isCi
          ? `Workflow step runs in a CI context where artifact tampering after ` +
            `test is observationally straightforward; the ordering proof is the ` +
            `step's placement in the workflow file.`
          : `npm guarantees the ordering test → ${fact.hookOrWorkflow} → pack, so ` +
            `the tamper provably happens post-test.`,
      )
      .factor(
        "build_dir_target",
        0.12,
        `Target is a build-output directory (${fact.buildDirs.join(", ")}), not ` +
          `a source directory — this distinguishes L12 from source-file edits ` +
          `covered by other rules.`,
      )
      .factor(
        fact.buildToolCamouflage ? "build_tool_camouflage" : "no_build_tool_camouflage",
        fact.buildToolCamouflage ? 0.05 : 0,
        fact.buildToolCamouflage
          ? `A build tool (tsc / esbuild / rollup / ...) appears in the same ` +
            `command chain. Camouflage does not reduce the finding — the tamper ` +
            `verb is what matters — but it increases intent confidence.`
          : `No build-tool camouflage; the tamper verb is the command's sole purpose.`,
      )
      .factor(
        fact.provenancePresent ? "provenance_present" : "no_provenance_mitigation",
        fact.provenancePresent ? -0.1 : 0.08,
        fact.provenancePresent
          ? `Sigstore provenance is configured — partial mitigation (coverage of ` +
            `post-tamper bytes must still be verified).`
          : `No Sigstore provenance — consumers cannot detect the tamper at ` +
            `install time.`,
      )
      .factor(
        fact.artifactFetch ? "cross_job_artifact_fetch" : "single_job_tamper",
        fact.artifactFetch ? 0.05 : 0,
        fact.artifactFetch
          ? `The workflow fetches and re-uploads artifacts, the specific shape ` +
            `the Shai-Hulud worm used to poison upstream packages.`
          : `No inter-job artifact flow observed; the tamper is local to one job.`,
      )
      .reference({
        id: "CVE-2025-30066",
        title:
          "tj-actions/changed-files GitHub Action tag poisoning — CI secret " +
          "exfiltration and build tampering precedent",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-30066",
        year: 2025,
        relevance:
          `CVE-2025-30066 is the live exemplar of the L12 primitive in a CI ` +
          `setting. SLSA Build Integrity v1.1 formally prohibits post-build ` +
          `artifact modification; this finding documents the specific violation ` +
          `at the command level.`,
      })
      .verification(stepInspectTamperSite(fact))
      .verification(stepReproduceModification(fact))
      .verification(stepCheckProvenance(fact));

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
      `L12 charter caps confidence at ${cap}. Benign post-build modifications ` +
      `exist (version stamping, licence banner injection, polyfill shimming); ` +
      `static analysis cannot always distinguish them from credential ` +
      `injection or integrity-check removal without reading the full command's ` +
      `intent.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new BuildArtifactTamperingRule());

export { BuildArtifactTamperingRule };
