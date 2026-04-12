/**
 * Rule: eu-ai-act-art13-transparency
 *
 * Deterministic checks on initialize_metadata for Art.13 transparency.
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
import { makeBundle, standardJudge } from "../../../rule-kit/index.js";

interface Art13Failure {
  id:
    | "missing-server-version"
    | "empty-server-instructions";
  description: string;
}

interface Art13Facts {
  art13_failures: Art13Failure[];
  has_server_version: boolean;
  has_server_instructions: boolean;
}

const METADATA: ComplianceRuleMetadata = {
  id: "eu-ai-act-art13-transparency",
  name: "EU AI Act Article 13 — Transparency & Information to Users",
  severity: "medium",
  intent:
    "An MCP server claiming EU AI Act Art.13 compliance MUST populate initialize_metadata.server_version and initialize_metadata.server_instructions so deployers can interpret and reproduce behaviour.",
  applies_to: [
    {
      framework: "eu_ai_act",
      category: "Article 13 — Transparency & Information to Users",
      control: "Art.13",
      sub_control: "Art.13(1-3)",
    },
  ],
  threat_refs: [
    {
      id: "EU-AI-Act-Art13-1",
      title: "EU AI Act Art.13(1) — transparency baseline",
      year: 2024,
      relevance: "Direct legal basis for requiring deployer-facing transparency.",
    },
    {
      id: "EU-AI-Act-Art13-2",
      title: "EU AI Act Art.13(2) — mandatory information to deployers",
      year: 2024,
      relevance: "Defines the content that server_instructions structurally carries.",
    },
    {
      id: "ISO-42001-A81",
      title: "ISO 42001 Annex A.8.1 — AI system transparency",
      relevance: "Parallel AI management system clause accepted as Art.13 evidence.",
    },
  ],
  strategies: ["shadow-state", "trust-inversion", "audit-erasure"],
  remediation:
    "Populate server_version with a semver string, populate server_instructions with a plain-language operator summary including destructive capabilities and human-oversight requirements, and keep both in sync with release notes.",
};

class EUAIActArt13TransparencyRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const meta = context.initialize_metadata ?? null;
    const version = meta?.server_version ?? null;
    const instructions = meta?.server_instructions ?? null;

    const hasVersion = typeof version === "string" && version.trim().length > 0;
    const hasInstructions =
      typeof instructions === "string" && instructions.trim().length > 0;

    const failures: Art13Failure[] = [];
    const pointers: EvidencePointer[] = [];

    if (!hasVersion) {
      failures.push({
        id: "missing-server-version",
        description:
          "initialize_metadata.server_version is missing or empty — Art.13 reproducibility impossible.",
      });
      pointers.push({
        kind: "initialize-field",
        label: "missing-server-version",
        location: "initialize_metadata.server_version",
      });
    }
    if (!hasInstructions) {
      failures.push({
        id: "empty-server-instructions",
        description:
          "initialize_metadata.server_instructions is missing or empty — deployers have no operator summary.",
      });
      pointers.push({
        kind: "initialize-field",
        label: "empty-server-instructions",
        location: "initialize_metadata.server_instructions",
      });
    }

    const facts: Art13Facts = {
      art13_failures: failures,
      has_server_version: hasVersion,
      has_server_instructions: hasInstructions,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary:
        failures.length > 0
          ? `${failures.length} EU AI Act Art.13 transparency failure(s)`
          : `Art.13 transparency fields populated`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: failures.length > 0,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as Art13Facts;
    const deterministicIds = (facts.art13_failures ?? []).map((f) => f.id);
    const result = standardJudge({
      raw,
      deterministic: deterministicIds,
      ruleId: this.metadata.id,
    });
    return {
      ...raw,
      judge_confirmed: result.confirmed,
      judge_rationale: result.rationale,
    };
  }
}

export const euAIActArt13TransparencyRule = new EUAIActArt13TransparencyRule();
