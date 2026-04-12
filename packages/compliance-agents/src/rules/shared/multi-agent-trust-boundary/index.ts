/**
 * Rule: multi-agent-trust-boundary
 *
 * Detects the shared-memory / cross-agent relay pattern: a server
 * exposes both writers and readers against the same logical resource
 * with no declared trust boundary. Walks the capability graph and
 * input channels; no regex, no static lists.
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

interface RelayTool {
  tool_name: string;
  roles: string[];
  annotated_trust: boolean;
}

interface TrustBoundaryFacts {
  writer_count: number;
  reader_count: number;
  untrusted_relay_tools: RelayTool[];
  shared_memory_pattern: boolean;
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-multi-agent-trust-boundary",
  name: "Multi-Agent Trust Boundary",
  severity: "high",
  intent:
    "Cross-agent relay tools MUST declare a trust boundary annotation and MUST NOT co-expose shared-memory read/write pairs without integrity tagging.",
  applies_to: [
    { framework: "owasp_asi", category: "ASI07 — Insecure Inter-Agent Communication", control: "ASI07" },
    { framework: "owasp_mcp", category: "MCP04 — Data Exfiltration", control: "MCP04" },
    { framework: "cosai", category: "T9 — Tool Abuse", control: "T9" },
    { framework: "maestro", category: "L7 — Agent Ecosystem", control: "L7" },
    { framework: "eu_ai_act", category: "Article 14 — Human Oversight", control: "Art.14" },
    { framework: "mitre_atlas", category: "AML.T0059 — Memory Manipulation", control: "AML.T0059" },
  ],
  threat_refs: [
    {
      id: "EmbraceTheRed-2025-11",
      title: "Prompt injection cascade in multi-agent AutoGen",
      year: 2025,
      relevance: "Documented cross-agent pollution via MCP tools that lack trust boundaries.",
    },
    {
      id: "InvariantLabs-2026-01",
      title: "Cross-agent memory poisoning via shared MCP state",
      year: 2026,
      relevance: "Research on shared vector store pollution propagating injections across agents.",
    },
    {
      id: "TrailOfBits-2026-02",
      title: "Trust boundaries in agentic AI systems",
      year: 2026,
      relevance: "Formal model showing why annotation-less relay tools propagate compromise.",
    },
    {
      id: "OWASP-ASI07",
      title: "OWASP Agentic Top 10 — Insecure Inter-Agent Communication",
      relevance: "Names the failure class this rule structurally prevents.",
    },
    {
      id: "MITRE-AML.T0059",
      title: "MITRE ATLAS Memory Manipulation",
      relevance: "Taxonomy anchor for the shared-memory poisoning attack path.",
    },
  ],
  strategies: ["cross-tool-flow", "shadow-state", "trust-inversion"],
  remediation:
    "Declare trust boundaries explicitly: add a trustBoundary annotation to every cross-agent relay tool, gate writes behind human-in-the-loop confirmation, and avoid exposing shared-memory read/write pairs in a single server without integrity tagging.",
};

class MultiAgentTrustBoundaryRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const graph = graphFor(context);

    let writers = 0;
    let readers = 0;
    const relays: RelayTool[] = [];

    for (const node of graph.nodes) {
      const caps = node.capabilities.map((c) => c.capability);
      const isWriter = caps.includes("writes-data");
      const isReader = caps.includes("reads-private-data") || caps.includes("reads-public-data");
      if (isWriter) writers++;
      if (isReader) readers++;

      const roles: string[] = [];
      if (isWriter) roles.push("writer");
      if (isReader) roles.push("reader");
      if (roles.length === 0) continue;

      const annotations =
        (context.tools ?? []).find((t) => t.name === node.name)?.annotations ??
        {};
      const trustMarkerKeys: string[] = [];
      for (const key of CONSENT_MARKER_KEYS) {
        if (typeof (annotations as Record<string, unknown>)[key] !== "undefined") {
          trustMarkerKeys.push(key);
        }
      }
      const annotatedTrust = trustMarkerKeys.length > 0;

      // A tool is a trust-relay risk if it writes (propagates injections)
      // OR if the server exposes both writers and readers together AND the
      // tool carries no trust annotation.
      if (isWriter && !annotatedTrust) {
        relays.push({ tool_name: node.name, roles, annotated_trust: false });
      }
    }

    const sharedMemoryPattern = writers > 0 && readers > 0;

    const pointers: EvidencePointer[] = [];
    for (const relay of relays) {
      pointers.push({
        kind: "tool",
        label: "cross-agent relay writer without trust boundary",
        location: `tool:${relay.tool_name}`,
        observed: `roles=${relay.roles.join("+")}; annotated=false`,
      });
    }
    if (sharedMemoryPattern) {
      pointers.push({
        kind: "capability",
        label: "shared-memory pattern: writers + readers in same server",
        location: `writers:${writers}/readers:${readers}`,
        observed: "co-exposed read/write with no integrity tagging",
      });
    }

    const deterministicViolation = sharedMemoryPattern && relays.length > 0;

    const facts: TrustBoundaryFacts = {
      writer_count: writers,
      reader_count: readers,
      untrusted_relay_tools: relays,
      shared_memory_pattern: sharedMemoryPattern,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary: deterministicViolation
        ? `Shared-memory pattern with ${relays.length} untrusted relay tool(s)`
        : `writers=${writers}, readers=${readers}, untrusted relays=${relays.length}`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: deterministicViolation,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as TrustBoundaryFacts;
    const result = standardJudge({
      raw,
      deterministic: facts.untrusted_relay_tools ?? [],
      ruleId: this.metadata.id,
    });
    return {
      ...raw,
      judge_confirmed: result.confirmed,
      judge_rationale: result.rationale,
    };
  }
}

export const multiAgentTrustBoundaryRule = new MultiAgentTrustBoundaryRule();
