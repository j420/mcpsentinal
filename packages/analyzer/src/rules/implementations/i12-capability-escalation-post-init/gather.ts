import type { AnalysisContext } from "../../../engine.js";
import {
  MCP_CAPABILITIES,
  type CapabilitySpec,
  type McpCapabilityKey,
} from "../_shared/protocol-shape-catalogue.js";

export interface I12UndeclaredFact {
  capability: McpCapabilityKey;
  spec: CapabilitySpec;
  matched_tokens: string[];
}

export interface I12GatherResult {
  facts: I12UndeclaredFact[];
}

export function gatherI12(context: AnalysisContext): I12GatherResult {
  const facts: I12UndeclaredFact[] = [];
  const src = context.source_code ?? "";
  if (!src) return { facts };
  const declared = context.declared_capabilities ?? null;
  if (!declared) return { facts };

  for (const [key, spec] of Object.entries(MCP_CAPABILITIES)) {
    const capKey = key as McpCapabilityKey;
    const wasDeclared = Boolean(
      (declared as Record<string, boolean | undefined>)[capKey],
    );
    if (wasDeclared) continue;

    const matches: string[] = [];
    for (const token of spec.handler_tokens) {
      if (src.includes(token)) matches.push(token);
    }
    if (matches.length === 0) continue;
    facts.push({ capability: capKey, spec, matched_tokens: matches });
  }
  return { facts };
}
