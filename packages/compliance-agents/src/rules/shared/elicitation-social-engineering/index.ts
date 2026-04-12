/**
 * Rule: elicitation-social-engineering
 *
 * Detects tools that request credential or identifier data from the
 * user via the MCP elicitation channel without consent annotations.
 * Walks capability graph input channels — no regex, no static lists.
 */

import type { AnalysisContext } from "@mcp-sentinel/analyzer";

import {
  ComplianceRule,
  type ComplianceRuleMetadata,
} from "../../base-rule.js";
import type {
  EvidenceBundle,
  EvidencePointer,
  JudgedTestResult,
  RawTestResult,
} from "../../../types.js";
import {
  CONSENT_MARKER_KEYS,
  graphFor,
  makeBundle,
  standardJudge,
} from "../../../rule-kit/index.js";

interface ElicitationPath {
  tool_name: string;
  credential_params: string[];
  identifier_params: string[];
  annotated: boolean;
}

interface ElicitationFacts {
  elicitation_credential_paths: ElicitationPath[];
  sampling_declared: boolean;
  total_credential_surface: number;
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-elicitation-social-engineering",
  name: "Elicitation Social Engineering",
  severity: "critical",
  intent:
    "Tools MUST NOT use the elicitation channel to harvest credentials, identifiers, or PII without consent annotations and an out-of-band auth flow.",
  applies_to: [
    { framework: "owasp_mcp", category: "MCP04 — Data Exfiltration", control: "MCP04" },
    { framework: "owasp_asi", category: "ASI03 — Identity & Privilege Abuse", control: "ASI03" },
    { framework: "cosai", category: "T1 — Identity & Access", control: "T1" },
    { framework: "cosai", category: "T5 — Data Exfiltration", control: "T5" },
    { framework: "maestro", category: "L6 — Security/Safety", control: "L6" },
    { framework: "eu_ai_act", category: "Article 13 — Transparency", control: "Art.13" },
    { framework: "mitre_atlas", category: "AML.T0055 — Credential Abuse", control: "AML.T0055" },
  ],
  threat_refs: [
    {
      id: "CVE-2025-ELICIT",
      title: "MCP elicitation credential harvest",
      year: 2025,
      relevance: "Documented case of a compromised MCP server using elicitation to collect OAuth tokens.",
    },
    {
      id: "OWASP-ASI03",
      title: "OWASP Agentic Top 10 — Identity & Privilege Abuse",
      relevance: "Names the failure class this rule structurally prevents.",
    },
    {
      id: "NIST-SP-800-63B",
      title: "NIST SP 800-63B — Identity proofing",
      relevance: "Defines the proper credential lifecycle that elicitation short-circuits.",
    },
  ],
  strategies: ["credential-laundering", "consent-bypass", "trust-inversion"],
  remediation:
    "Never use the elicitation capability for credential collection. Route credential flows through a centralized secrets manager and prefer OAuth 2.1 device flows. Add consent annotations to any tool that legitimately prompts the user.",
};

class ElicitationSocialEngineeringRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const graph = graphFor(context);
    const paths: ElicitationPath[] = [];
    let totalSurface = 0;

    for (const node of graph.nodes) {
      const credParams = node.input_channels
        .filter((ch) => ch.semantic === "credential")
        .map((ch) => ch.name);
      const idParams = node.input_channels
        .filter((ch) => ch.semantic === "identifier")
        .map((ch) => ch.name);
      const surface = credParams.length + idParams.length;
      if (surface === 0) continue;
      totalSurface += surface;

      const annotations =
        (context.tools ?? []).find((t) => t.name === node.name)?.annotations ??
        {};
      const annotated = CONSENT_MARKER_KEYS.some(
        (key) => typeof (annotations as Record<string, unknown>)[key] !== "undefined",
      );

      if (!annotated) {
        paths.push({
          tool_name: node.name,
          credential_params: credParams,
          identifier_params: idParams,
          annotated: false,
        });
      }
    }

    const samplingDeclared = Boolean(context.declared_capabilities?.sampling);

    const pointers: EvidencePointer[] = [];
    for (const path of paths) {
      pointers.push({
        kind: "tool",
        label: "tool harvests credentials via elicitation with no consent annotation",
        location: `tool:${path.tool_name}`,
        observed: `cred=${path.credential_params.join(",")}; id=${path.identifier_params.join(",")}`,
      });
    }

    const facts: ElicitationFacts = {
      elicitation_credential_paths: paths,
      sampling_declared: samplingDeclared,
      total_credential_surface: totalSurface,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary:
        paths.length > 0
          ? `${paths.length} tool(s) harvest credentials/identifiers via elicitation without consent gates`
          : `Credential surface=${totalSurface}, all gated by consent annotations`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: paths.length > 0,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as ElicitationFacts;
    const result = standardJudge({
      raw,
      deterministic: facts.elicitation_credential_paths ?? [],
      ruleId: this.metadata.id,
    });
    return {
      ...raw,
      judge_confirmed: result.confirmed,
      judge_rationale: result.rationale,
    };
  }
}

export const elicitationSocialEngineeringRule =
  new ElicitationSocialEngineeringRule();
