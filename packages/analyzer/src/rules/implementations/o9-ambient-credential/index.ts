/**
 * O9 — Ambient Credential Exploitation (Rule Standard v2).
 *
 * Detects filesystem reads targeting ambient user-scoped credential
 * paths (~/.aws, ~/.ssh, ~/.kube, ~/.docker, GOOGLE_APPLICATION_CREDENTIALS
 * indirection, etc.). Confidence cap 0.85; severity critical.
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
import { gatherO9, type AmbientCredentialSite } from "./gather.js";
import { stepInspectCallSite, stepInspectScope } from "./verification.js";

const RULE_ID = "O9";
const RULE_NAME = "Ambient Credential Exploitation";
const OWASP = "MCP04-data-exfiltration" as const;
const MITRE = "AML.T0057" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Never read ambient user-scoped credential files from an MCP " +
  "server process. Replace reads of ~/.aws/credentials, ~/.ssh/id_rsa, " +
  "~/.kube/config, ~/.docker/config.json, GOOGLE_APPLICATION_CREDENTIALS, " +
  "etc. with per-invocation explicit credential passing (the MCP client " +
  "forwards a scoped token). If a credential is genuinely needed, request " +
  "it through a declared MCP capability so the user can grant or deny. " +
  "CVE-2025-53109 and CVE-2025-53110 document how a compromised MCP " +
  "server's ambient reads produced full cloud account takeover.";

const STRATEGY_AMBIENT_PATH = "ambient-path-token-match";
const STRATEGY_HOMEDIR = "homedir-expansion-detection";
const STRATEGY_ENVVAR = "env-var-indirection-detection";
const STRATEGY_TEST_SKIP = "test-file-structural-skip";

class AmbientCredentialRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  readonly edgeCaseStrategies = [
    STRATEGY_AMBIENT_PATH,
    STRATEGY_HOMEDIR,
    STRATEGY_ENVVAR,
    STRATEGY_TEST_SKIP,
  ] as const;

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherO9(context);
    if (gathered.isTestFile) return [];
    return gathered.sites.map((s) => this.buildFinding(s)).slice(0, 10);
  }

  private buildFinding(site: AmbientCredentialSite): RuleResult {
    const chain = this.buildChain(site);
    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }

  private buildChain(site: AmbientCredentialSite): EvidenceChain {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.observed,
        rationale:
          `The expression reads ${site.label}. This file holds the ` +
          `user's ambient authentication material for every CLI tool ` +
          `that relies on it. The MCP server inherits that delegated ` +
          `authority without any consent step.`,
      })
      .propagation({
        propagation_type: "function-call",
        location: site.location,
        observed:
          `fs-read primitive invoked with a ${site.kind} that resolves ` +
          `to the ambient credential store.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: site.location,
        observed: `Ambient credential read: ${site.label}`,
      })
      .impact({
        impact_type: "credential-theft",
        scope: "user-data",
        exploitability: "trivial",
        scenario:
          `The credential at ${site.label} authenticates against every ` +
          `cloud account / host / cluster / registry the user has ever ` +
          `configured. A single successful read converts to persistent ` +
          `third-party access — remediation requires rotating every ` +
          `affected credential.`,
      })
      .factor(
        "ambient_credential_path_observed",
        0.18,
        `AST marker "${site.marker}" matched ambient-path vocabulary ` +
          `(${STRATEGY_AMBIENT_PATH} / ${STRATEGY_HOMEDIR} / ${STRATEGY_ENVVAR}).`,
      )
      .factor(
        "server_process_inherits_authority",
        0.10,
        `The MCP server runs with the user's fs authority and ` +
          `therefore sees the credential file without any explicit ` +
          `grant.`,
      )
      .reference({
        id: "CVE-2025-53109",
        title: "Anthropic filesystem MCP server root boundary bypass",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-53109",
        relevance:
          "Documents how ambient-credential access from a compromised " +
          "MCP server produced full cloud account takeover — same " +
          "attack pattern this rule detects statically.",
      });

    builder.verification(stepInspectCallSite(site));
    builder.verification(stepInspectScope(site));

    const chain = builder.build();
    return capConfidence(chain, CONFIDENCE_CAP);
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `O9 charter caps confidence at ${cap}. A vanishingly rare ` +
      `legitimate use exists — a server whose own configuration ` +
      `happens to live at a path that shares a fragment with the ` +
      `ambient vocabulary; ${STRATEGY_TEST_SKIP} already removes ` +
      `test-file false positives.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new AmbientCredentialRule());

export { AmbientCredentialRule };
