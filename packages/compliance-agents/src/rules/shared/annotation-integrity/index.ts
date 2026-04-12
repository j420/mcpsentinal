/**
 * Rule: annotation-integrity
 *
 * Detects mismatches between declared tool annotations
 * (readOnlyHint, idempotentHint, openWorldHint) and the structural
 * capability graph. This is the broader annotation-deception rule;
 * destructive-operation-gating handles the destructiveHint-specific
 * case. No regex, no static lists.
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
  graphFor,
  makeBundle,
  standardJudge,
} from "../../../rule-kit/index.js";

interface LyingAnnotation {
  tool_name: string;
  lie: string;
  capability_evidence: string[];
}

interface IntegrityFacts {
  lying_annotations: LyingAnnotation[];
  inspected_tools: number;
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-annotation-integrity",
  name: "Annotation Integrity",
  severity: "high",
  intent:
    "Tool annotations (readOnlyHint, idempotentHint, openWorldHint) MUST match the structural capability graph so clients can make correct safety and retry decisions.",
  applies_to: [
    { framework: "owasp_mcp", category: "MCP02 — Tool Poisoning", control: "MCP02" },
    { framework: "owasp_asi", category: "ASI02 — Tool Misuse", control: "ASI02" },
    { framework: "cosai", category: "T4 — Prompt Injection", control: "T4" },
    { framework: "maestro", category: "L3 — Deployment Integrity", control: "L3" },
    { framework: "eu_ai_act", category: "Article 13 — Transparency", control: "Art.13" },
    { framework: "mitre_atlas", category: "AML.T0054 — LLM Prompt Injection", control: "AML.T0054" },
  ],
  threat_refs: [
    {
      id: "I1-MCP-Sentinel",
      title: "Analyzer rule I1 — Annotation Deception",
      relevance: "Existing deterministic rule on destructiveHint; this rule extends the pattern to the full annotation surface.",
    },
    {
      id: "Invariant-2025-IDEM",
      title: "idempotentHint=true on non-idempotent tool",
      year: 2025,
      relevance: "Duplicate production writes caused by annotation lie.",
    },
    {
      id: "MCP-Spec-2025-03-26",
      title: "MCP specification 2025-03-26",
      year: 2025,
      relevance: "Introduced idempotentHint and openWorldHint as first-class annotations.",
    },
    {
      id: "OWASP-MCP02",
      title: "OWASP MCP Top 10 — Tool Poisoning",
      relevance: "Names the failure class this rule structurally prevents.",
    },
  ],
  strategies: ["trust-inversion", "shadow-state", "consent-bypass"],
  remediation:
    "Never set readOnlyHint=true on a tool that writes data. Never set idempotentHint=true on a non-idempotent tool. Never set openWorldHint=false on a tool that issues network calls. Omit the annotation when uncertain so the client's conservative default applies.",
};

class AnnotationIntegrityRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const graph = graphFor(context);
    const lies: LyingAnnotation[] = [];
    let inspected = 0;

    for (const node of graph.nodes) {
      inspected++;
      const caps = node.capabilities.map((c) => c.capability);
      const annotations =
        ((context.tools ?? []).find((t) => t.name === node.name)?.annotations ??
          {}) as Record<string, unknown>;

      const readOnlyHint = annotations["readOnlyHint"];
      const idempotentHint = annotations["idempotentHint"];
      const openWorldHint = annotations["openWorldHint"];

      const hasWrite = caps.includes("writes-data") || caps.includes("destructive");
      const hasExec = caps.includes("executes-code");
      const hasNetwork = caps.includes("sends-network") || caps.includes("receives-network");

      if (readOnlyHint === true && (hasWrite || hasExec)) {
        lies.push({
          tool_name: node.name,
          lie: "readOnlyHint=true but tool has write/destructive/executes-code capability",
          capability_evidence: caps,
        });
      }
      if (idempotentHint === true && hasWrite) {
        lies.push({
          tool_name: node.name,
          lie: "idempotentHint=true but tool has writes-data capability",
          capability_evidence: caps,
        });
      }
      if (openWorldHint === false && hasNetwork) {
        lies.push({
          tool_name: node.name,
          lie: "openWorldHint=false but tool has network capability",
          capability_evidence: caps,
        });
      }
    }

    const pointers: EvidencePointer[] = lies.map((l) => ({
      kind: "tool",
      label: "annotation disagrees with capability graph",
      location: `tool:${l.tool_name}`,
      observed: l.lie,
    }));

    const facts: IntegrityFacts = {
      lying_annotations: lies,
      inspected_tools: inspected,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary:
        lies.length > 0
          ? `${lies.length} annotation lie(s) across ${inspected} tools`
          : `${inspected} tools inspected, all annotations consistent with capabilities`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: lies.length > 0,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as IntegrityFacts;
    const result = standardJudge({
      raw,
      deterministic: facts.lying_annotations ?? [],
      ruleId: this.metadata.id,
    });
    return {
      ...raw,
      judge_confirmed: result.confirmed,
      judge_rationale: result.rationale,
    };
  }
}

export const annotationIntegrityRule = new AnnotationIntegrityRule();
