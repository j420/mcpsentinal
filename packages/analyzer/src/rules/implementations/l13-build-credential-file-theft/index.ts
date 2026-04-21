/**
 * L13 — Build Credential File Theft (Rule Standard v2).
 *
 * REPLACES the L13 (CredentialFileTheftRule) class in
 * `packages/analyzer/src/rules/implementations/advanced-supply-chain-detector.ts`.
 *
 * Two detection paths:
 *   - Taint chain (via shared taint-rule-kit): credential-file read
 *     whose bytes flow to a network egress sink. Produces a full
 *     source→propagation→sink chain via shared builder.
 *   - Structural fallback: standalone fs.readFile call on a known
 *     credential file path, OR a Dockerfile COPY / ADD instruction
 *     that bakes the credential into the image.
 *
 * No regex literals outside `data/`.
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
import {
  buildTaintChain,
  capConfidence,
  type TaintChainDescriptor,
} from "../_shared/taint-rule-kit/index.js";
import { gatherL13, type L13Fact } from "./gather.js";
import { stepsForFact } from "./verification.js";

const RULE_ID = "L13";
const RULE_NAME = "Build Credential File Theft";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0057" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Never read credential files (.npmrc, .pypirc, .docker/config.json, " +
  ".ssh/id_*, .aws/credentials, ~/.config/gh/hosts.yml) from runtime " +
  "MCP server code or build scripts. Rotate the affected secrets " +
  "immediately if such a read is already deployed. Use environment " +
  "variables for tokens (NPM_TOKEN, ANTHROPIC_API_KEY) injected at " +
  "runtime by the CI secret manager — never baked into the image. " +
  "In CI, prefer OIDC exchange (actions/create-github-app-token, " +
  "`permissions: id-token: write`) for short-lived credentials with " +
  "no file-based storage. When a Dockerfile must consume a credential " +
  "at build time, use BuildKit's `--mount=type=secret,id=<name>` so " +
  "the credential is available during RUN but is not present in any " +
  "image layer.";

const TAINT_DESCRIPTOR: TaintChainDescriptor = {
  ruleId: RULE_ID,
  sourceType: "file-content",
  sinkType: "network-send",
  cvePrecedent: "CVE-2025-55155",
  impactType: "credential-theft",
  impactScope: "connected-services",
  sourceRationale: (fact) =>
    `Credential-file read observed: "${fact.sourceExpression.slice(0, 120)}". ` +
    `The file contains long-lived publish tokens or bearer credentials. ` +
    `Any downstream transmission of its bytes is exfiltration.`,
  impactScenario: (fact) =>
    `Credential bytes flow from the file-read source to the network ` +
    `sink "${fact.sinkExpression.slice(0, 120)}" through ${fact.path.length} ` +
    `propagation hop(s) without sanitisation. Captured tokens enable the ` +
    `attacker to publish backdoored versions under the victim's identity — ` +
    `the propagation vector of the Shai-Hulud worm (CVE-2025-55155, ` +
    `September 2025) that self-replicated across the npm ecosystem.`,
  threatReference: {
    id: "CVE-2025-55155",
    title: "Shai-Hulud self-replicating npm worm exfiltrates .npmrc tokens during install",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2025-55155",
    relevance:
      "The worm's payload was exactly this rule's detection pattern: " +
      "read .npmrc, extract _authToken, POST to attacker URL, re-publish " +
      "infected package under the victim's account.",
  },
  unmitigatedDetail:
    "No redaction function was observed between the credential-file " +
    "read and the network sink. The full file contents — including " +
    "bearer tokens — reach the attacker-controlled endpoint.",
  mitigatedCharterKnownDetail: (name) =>
    `Observed sanitiser ${name} is on the charter-audited list, but ` +
    `L13's charter lists NO safe redactor. This branch should not be reached.`,
  mitigatedCharterUnknownDetail: (name) =>
    `Observed sanitiser "${name}" — a reviewer must confirm the body strips ` +
    `bearer tokens before the network send. No canonical library exists ` +
    `for this; the sanitiser IS the reviewer's responsibility.`,
};

class BuildCredentialFileTheftRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "composite"; // taint + structural

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherL13(context);
    if (gathered.mode !== "facts") return [];
    return gathered.facts.map((f) => this.buildFinding(f));
  }

  private buildFinding(fact: L13Fact): RuleResult {
    if (fact.kind === "taint-cred-to-network" && fact.taintFact) {
      return this.buildTaintFinding(fact);
    }
    return this.buildStructuralFinding(fact);
  }

  private buildTaintFinding(fact: L13Fact): RuleResult {
    const builder = buildTaintChain(fact.taintFact!, TAINT_DESCRIPTOR);

    builder.factor(
      "cred_file_path_substring",
      0.15,
      `Credential-file substring "${fact.credFile}" observed in the source ` +
        `expression, propagation path, or sink argument. This is the ` +
        `specific credential storage pattern L13 targets.`,
    );
    builder.factor(
      "taint_flow_to_network_sink",
      0.1,
      "Full AST / lightweight taint path proves the credential bytes reach " +
        "a network sink without observable redaction.",
    );
    builder.factor(
      "no_input_validation_on_exfil",
      0.08,
      "No sanitiser identified on the flow — even if one appears in a " +
        "wrapper, redacting bearer tokens is not a library function a " +
        "static rule can validate; manual review is required.",
    );

    const steps = stepsForFact(fact);
    for (const s of steps) builder.verification(s);

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP, RULE_ID);

    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }

  private buildStructuralFinding(fact: L13Fact): RuleResult {
    const isDockerfile = fact.kind === "dockerfile-copy-cred";
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: fact.location,
        observed: fact.observed.slice(0, 200),
        rationale: isDockerfile
          ? `Dockerfile instruction copies "${fact.credFile}" into the built ` +
            `image. The credential becomes part of the image layer and is ` +
            `extractable by anyone who can pull the image.`
          : `Runtime code reads "${fact.credFile}" — a known credential ` +
            `storage path. Even if the bytes never reach a network call ` +
            `in the scanned scope, loading the credential into process ` +
            `memory creates theft opportunities via logging, error ` +
            `messages, or tool response serialisation.`,
      })
      .propagation({
        propagation_type: isDockerfile ? "direct-pass" : "variable-assignment",
        location: fact.location,
        observed: isDockerfile
          ? `COPY / ADD baked the credential into the image layer.`
          : `Credential file content is loaded into process memory with no observable scope reduction.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: fact.location,
        observed: isDockerfile
          ? `Image layer contains "${fact.credFile}" — extractable via docker cp / docker image inspect`
          : `${fact.credFile} content resident in process memory`,
        cve_precedent: "CVE-2025-55155",
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: fact.location,
        detail: isDockerfile
          ? "BuildKit's --mount=type=secret is not in use; the credential is a first-class image layer artefact."
          : "No scope reduction (close, unref, explicit clearing) observed.",
      })
      .impact({
        impact_type: "credential-theft",
        scope: "connected-services",
        exploitability: isDockerfile ? "trivial" : "moderate",
        scenario: isDockerfile
          ? `Anyone who pulls or inspects the image can extract the ` +
            `credential with \`docker cp <container>:${fact.credFile}\` or ` +
            `\`docker save | tar -x\`. The Shai-Hulud worm (CVE-2025-55155) ` +
            `demonstrated that a single leaked npm publish token is ` +
            `sufficient to propagate a worm across thousands of downstream ` +
            `packages.`
          : `Any code path that logs, serialises, or returns the loaded ` +
            `file content (including an error response that includes the ` +
            `raw file bytes) leaks the credential. The Shai-Hulud worm ` +
            `(CVE-2025-55155) used this exact read-and-leak pattern — the ` +
            `leak-to-network step happened outside the scanned scope.`,
      })
      .factor(
        "cred_file_path_substring",
        0.15,
        `Credential-file substring "${fact.credFile}" matched in ${isDockerfile ? "Dockerfile" : "runtime code"}.`,
      )
      .factor(
        "taint_flow_to_network_sink",
        0,
        "No full taint chain to a network sink observed — the flow may complete out of scope.",
      )
      .factor(
        "no_input_validation_on_exfil",
        0.08,
        isDockerfile
          ? "Dockerfile does not use BuildKit --mount=type=secret; no build-time redaction."
          : "Runtime code does not reduce the file content's scope after the read.",
      )
      .reference({
        id: "CVE-2025-55155",
        title: "Shai-Hulud npm worm — .npmrc token exfiltration chain",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-55155",
        relevance:
          "The worm's payload performed the exact read-and-leak pattern " +
          "this finding detects. Baking the credential into an image " +
          "layer is the persistent-storage equivalent.",
      });

    const steps = stepsForFact(fact);
    for (const s of steps) builder.verification(s);

    const chain = capChainConfidence(builder.build(), CONFIDENCE_CAP);

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

function capChainConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `L13 charter caps confidence at ${cap}. Legitimate tooling ` +
      `(npm's own config subcommands, CI setup scripts that WRITE an .npmrc ` +
      `to authenticate the publish step) legitimately touch credential ` +
      `files; the rule cannot always distinguish benign CI setup from ` +
      `exfiltration without a runtime trace.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new BuildCredentialFileTheftRule());

export { BuildCredentialFileTheftRule };
