/**
 * Rule: consent-fatigue-resistance
 *
 * Detects the Invariant-Labs pattern: a pile of benign tools hiding a
 * few destructive ones with no per-tool consent annotations. Fully
 * structural: walks the capability graph and inspects annotation keys
 * from the centralized marker catalog in rule-kit.
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

interface DangerTool {
  tool_name: string;
  capabilities: string[];
  annotated: boolean;
  annotation_keys_present: string[];
}

interface FatigueFacts {
  benign_count: number;
  dangerous_count: number;
  ratio: number;
  unannotated_dangerous_tools: DangerTool[];
  annotated_dangerous_tools: DangerTool[];
}

const RATIO_THRESHOLD = 10;

const METADATA: ComplianceRuleMetadata = {
  id: "shared-consent-fatigue-resistance",
  name: "Consent Fatigue Resistance",
  severity: "high",
  intent:
    "A server MUST NOT hide destructive or code-executing tools inside a large set of benign tools without per-tool consent annotations that resist approval fatigue.",
  applies_to: [
    { framework: "owasp_mcp", category: "MCP06 — Excessive Permissions", control: "MCP06" },
    { framework: "owasp_asi", category: "ASI09 — Human Oversight", control: "ASI09" },
    { framework: "cosai", category: "T2 — Human-in-the-Loop", control: "T2" },
    { framework: "cosai", category: "T9 — Tool Abuse", control: "T9" },
    { framework: "maestro", category: "L6 — Security/Safety", control: "L6" },
    { framework: "eu_ai_act", category: "Article 14 — Human Oversight", control: "Art.14" },
  ],
  threat_refs: [
    {
      id: "Invariant-Labs-2025",
      title: "Consent fatigue in agentic MCP clients",
      year: 2025,
      relevance: "Documented the 84.2% tool poisoning success rate under auto-approve flows.",
    },
    {
      id: "OWASP-ASI09",
      title: "OWASP Agentic Top 10 — Human Oversight",
      relevance: "Names the failure class this rule structurally prevents.",
    },
    {
      id: "OWASP-MCP06",
      title: "OWASP MCP Top 10 — Excessive Permissions",
      relevance: "Approval-overhead anti-patterns are explicitly called out as MCP06 enablers.",
    },
    {
      id: "CVE-2025-FATIGUE",
      title: "MCP client auto-approve exploit against file manager",
      year: 2025,
      relevance: "Real-world reproduction of the consent-fatigue attack pattern.",
    },
  ],
  strategies: ["consent-bypass", "human-oversight-bypass", "trust-inversion"],
  remediation:
    "Annotate every destructive, code-executing, or credential-handling tool with a consent marker (requiresConfirmation / humanInTheLoop / needsApproval / confirmationRequired / userMustApprove). Consider splitting dangerous tools into a separate MCP server the user must approve with a distinct, informed consent step.",
};

class ConsentFatigueResistanceRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const graph = graphFor(context);

    const dangerous: DangerTool[] = [];
    let benignCount = 0;

    for (const node of graph.nodes) {
      const caps = node.capabilities ?? [];
      const capNames = caps.map((c) => c.capability);
      const isDangerous = capNames.some(
        (c) =>
          c === "destructive" ||
          c === "executes-code" ||
          c === "manages-credentials" ||
          c === "writes-data",
      );
      const toolAnnotations =
        (context.tools ?? []).find((t) => t.name === node.name)?.annotations ??
        {};
      const annotationKeysPresent: string[] = [];
      for (const key of CONSENT_MARKER_KEYS) {
        if (typeof (toolAnnotations as Record<string, unknown>)[key] !== "undefined") {
          annotationKeysPresent.push(key);
        }
      }
      const annotated = annotationKeysPresent.length > 0;

      if (isDangerous) {
        dangerous.push({
          tool_name: node.name,
          capabilities: capNames,
          annotated,
          annotation_keys_present: annotationKeysPresent,
        });
      } else {
        benignCount++;
      }
    }

    const unannotated = dangerous.filter((d) => !d.annotated);
    const annotated = dangerous.filter((d) => d.annotated);
    const ratio = dangerous.length === 0 ? 0 : benignCount / Math.max(1, dangerous.length);
    const fatigueTrigger = benignCount >= RATIO_THRESHOLD && unannotated.length > 0;

    const pointers: EvidencePointer[] = [];
    for (const tool of unannotated) {
      pointers.push({
        kind: "tool",
        label: "dangerous tool without consent annotation",
        location: `tool:${tool.tool_name}`,
        observed: `caps=${tool.capabilities.join("+")}`,
      });
    }
    if (fatigueTrigger) {
      pointers.push({
        kind: "capability",
        label: "consent-fatigue ratio exceeded",
        location: `benign:${benignCount} vs dangerous:${dangerous.length}`,
        observed: `ratio=${ratio.toFixed(2)} threshold=${RATIO_THRESHOLD}`,
      });
    }

    const facts: FatigueFacts = {
      benign_count: benignCount,
      dangerous_count: dangerous.length,
      ratio,
      unannotated_dangerous_tools: unannotated,
      annotated_dangerous_tools: annotated,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary: fatigueTrigger
        ? `Consent fatigue risk: ${benignCount} benign tools hiding ${unannotated.length} unannotated dangerous tool(s)`
        : `Benign:${benignCount}, dangerous:${dangerous.length}, unannotated:${unannotated.length}`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: fatigueTrigger,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as FatigueFacts;
    const result = standardJudge({
      raw,
      deterministic: facts.unannotated_dangerous_tools ?? [],
      ruleId: this.metadata.id,
    });
    return {
      ...raw,
      judge_confirmed: result.confirmed,
      judge_rationale: result.rationale,
    };
  }
}

export const consentFatigueResistanceRule = new ConsentFatigueResistanceRule();
