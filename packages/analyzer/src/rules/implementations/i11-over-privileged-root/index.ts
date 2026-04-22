/**
 * I11 — Over-Privileged Root (Rule Standard v2).
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
import type { Location } from "../../location.js";
import { gatherI11, type I11Fact } from "./gather.js";
import { I11_CONFIDENCE_CAP } from "./data/config.js";
import {
  stepInspectRootDeclaration,
  stepCrossReferenceCve,
} from "./verification.js";

const RULE_ID = "I11";
const RULE_NAME = "Over-Privileged Root";
const OWASP = "MCP06-excessive-permissions" as const;

const REMEDIATION =
  "Narrow the server's roots to the minimum scope required for its declared " +
  "function. Never declare roots at file:///, /etc, /root, ~, ~/.ssh, " +
  "~/.aws, /proc, /var. Prefer project-local roots (/workspace/my-project, " +
  "./data). When the server must access system paths, use the narrowest " +
  "possible prefix (/etc/hosts, not /etc). Cross-reference I4 for per-URI " +
  "filtering and I15 for transport session security.";

class OverPrivilegedRootRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { roots: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherI11(context);
    if (gathered.facts.length === 0) return [];
    return gathered.facts.map((f) => this.buildFinding(f));
  }

  private buildFinding(fact: I11Fact): RuleResult {
    const loc: Location = {
      kind: "resource",
      uri: fact.root_uri,
      field: "uri",
    };

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: loc,
        observed: `Root URI: ${fact.root_uri}`,
        rationale:
          `The server declares filesystem scope covering ${fact.match.kind} ` +
          `territory. ${fact.match.rationale}`,
      })
      .sink({
        sink_type: "file-write",
        location: loc,
        observed: `Root permits read/write within ${fact.match.kind} scope.`,
        cve_precedent: "CVE-2025-53109",
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          `Any tool in this server that accepts a path parameter can read ` +
          `(or, depending on the tool, write) within the declared root. ` +
          `CVE-2025-53109 demonstrated that root boundary bypass is in-the-` +
          `wild exploitable; overly broad roots amplify the blast radius.`,
      })
      .factor(
        "sensitive_root_matched",
        0.12,
        `Root path matches the sensitive catalogue entry ` +
          `"${fact.match.path_fragment}" (kind: ${fact.match.kind}).`,
      )
      .reference({
        id: "CVE-2025-53109",
        title: "Anthropic filesystem MCP server root-boundary bypass",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-53109",
        year: 2025,
        relevance:
          "Real-world precedent demonstrating that declared roots at " +
          "sensitive paths are catastrophic when client-level containment " +
          "fails.",
      })
      .verification(stepInspectRootDeclaration(fact))
      .verification(stepCrossReferenceCve(fact));

    if (fact.fence_hit) {
      builder.factor(
        "false_positive_fence_triggered",
        -0.1,
        `Root URI contains a fence token (${fact.match.false_positive_fence.join(", ")}) ` +
          `indicating a legitimate narrow scope variant.`,
      );
    }

    const chain = capConfidence(builder.build(), I11_CONFIDENCE_CAP);
    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: null,
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
    rationale: `I11 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new OverPrivilegedRootRule());

export { OverPrivilegedRootRule };
