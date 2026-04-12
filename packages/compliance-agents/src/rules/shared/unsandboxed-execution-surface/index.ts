/**
 * Rule: unsandboxed-execution-surface
 *
 * Deterministic violation when (a) capability graph contains a node with
 * `executes-code` and (b) source-file token scan shows no sandbox markers
 * (`SANDBOX_MARKERS` — seccomp/apparmor/gvisor/runAsNonRoot etc.).
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
  SANDBOX_MARKERS,
  graphFor,
  makeBundle,
  sourceTokenHits,
  standardJudge,
} from "../../../rule-kit/index.js";

interface ExecutionNode {
  tool_name: string;
  confidence: number;
  has_filesystem: boolean;
}

interface UnsandboxedFacts {
  execution_nodes: ExecutionNode[];
  sandbox_markers_found: string[];
  unsandboxed_surface: string;
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-unsandboxed-execution-surface",
  name: "Unsandboxed Execution Surface",
  severity: "high",
  intent:
    "A server exposing code-execution capability MUST run inside a structural sandbox (seccomp, apparmor, gvisor, runAsNonRoot, readOnlyRootFilesystem) to satisfy MCP07 / CoSAI T8 / EU AI Act Art.15.",
  applies_to: [
    { framework: "owasp_mcp", category: "MCP07 — Insecure Configuration", control: "MCP07" },
    { framework: "cosai", category: "T8 — Runtime Exploitation", control: "T8" },
    { framework: "maestro", category: "L4 — Deployment & Infrastructure", control: "L4" },
    { framework: "eu_ai_act", category: "Article 15 — Accuracy, Robustness, Cybersecurity", control: "Art.15" },
  ],
  threat_refs: [
    {
      id: "K19-MCP-Sentinel",
      title: "Analyzer rule K19 — Missing Runtime Sandbox Enforcement",
      relevance: "Existing deterministic rule; this charter lifts it into the compliance-framework reporter.",
    },
    {
      id: "CVE-2025-53109",
      title: "Anthropic mcp-server-filesystem root boundary bypass",
      year: 2025,
      relevance: "Real filesystem-escape CVE — the underlying failure mode is unsandboxed filesystem access.",
    },
    {
      id: "CVE-2025-53110",
      title: "Anthropic mcp-server-filesystem path validation bypass",
      year: 2025,
      relevance: "Companion CVE; same root cause — missing structural sandbox around executes-code path.",
    },
    {
      id: "OWASP-MCP07",
      title: "OWASP MCP Top 10 — Insecure Configuration",
      relevance: "Names the failure class this rule structurally prevents.",
    },
    {
      id: "CoSAI-T8",
      title: "CoSAI Threat T8 — Runtime Exploitation",
      relevance: "Taxonomy anchor for the post-exploitation blast radius this rule contains.",
    },
  ],
  strategies: ["privilege-chain", "boundary-leak", "config-drift"],
  remediation:
    "Add a structural sandbox: seccomp profile, AppArmor, gvisor/runsc, readOnlyRootFilesystem: true, runAsNonRoot: true, runAsUser: 1000, and drop all capabilities. Anchor the filesystem capability at a dedicated data directory — never /.",
};

class UnsandboxedExecutionSurfaceRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const graph = graphFor(context);
    const executionNodes: ExecutionNode[] = [];
    for (const node of graph.nodes) {
      const exec = node.capabilities.find(
        (c) => c.capability === "executes-code" && c.confidence >= 0.4,
      );
      if (!exec) continue;
      const hasFs = node.capabilities.some(
        (c) => c.capability === "accesses-filesystem" && c.confidence >= 0.4,
      );
      executionNodes.push({
        tool_name: node.name,
        confidence: exec.confidence,
        has_filesystem: hasFs,
      });
    }

    const sandboxHits = sourceTokenHits(context, SANDBOX_MARKERS);

    const deterministicViolation =
      executionNodes.length > 0 && sandboxHits.length === 0;

    const pointers: EvidencePointer[] = [];
    for (const node of executionNodes) {
      pointers.push({
        kind: "tool",
        label: "code-execution tool",
        location: `tool:${node.tool_name}`,
        observed: `executes-code (${node.confidence.toFixed(2)})${node.has_filesystem ? " + filesystem" : ""}`,
      });
    }
    if (deterministicViolation) {
      pointers.push({
        kind: "source-file",
        label: "unsandboxed_surface",
        location: "source_files",
        observed: "no seccomp / apparmor / gvisor / runAsNonRoot / readOnlyRootFilesystem markers",
      });
    }

    const facts: UnsandboxedFacts = {
      execution_nodes: executionNodes,
      sandbox_markers_found: sandboxHits,
      unsandboxed_surface: "unsandboxed_surface",
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary: deterministicViolation
        ? `${executionNodes.length} code-execution tool(s) with no sandbox markers`
        : `Execution nodes=${executionNodes.length}, sandbox markers=${sandboxHits.length}`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: deterministicViolation,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as UnsandboxedFacts;
    const deterministicNames: string[] = [];
    for (const node of facts.execution_nodes ?? []) {
      deterministicNames.push(node.tool_name);
    }
    if (
      (facts.execution_nodes ?? []).length > 0 &&
      (facts.sandbox_markers_found ?? []).length === 0
    ) {
      deterministicNames.push("unsandboxed_surface");
    }
    const result = standardJudge({
      raw,
      deterministic: deterministicNames,
      ruleId: this.metadata.id,
    });
    return {
      ...raw,
      judge_confirmed: result.confirmed,
      judge_rationale: result.rationale,
    };
  }
}

export const unsandboxedExecutionSurfaceRule =
  new UnsandboxedExecutionSurfaceRule();
