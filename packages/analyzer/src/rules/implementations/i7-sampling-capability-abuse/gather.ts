/**
 * I7 gather — detect sampling + content-ingestion coexistence.
 */

import type { AnalysisContext } from "../../../engine.js";
import { buildCapabilityGraph } from "../../analyzers/capability-graph.js";
import { I7_INGESTION_MIN_CONFIDENCE } from "./data/config.js";

export interface I7IngestionNode {
  tool_name: string;
  capability: string;
  confidence: number;
}

export interface I7Fact {
  sampling_declared: boolean;
  ingestion_nodes: I7IngestionNode[];
}

export interface I7GatherResult {
  fact: I7Fact | null;
}

export function gatherI7(context: AnalysisContext): I7GatherResult {
  const caps = context.declared_capabilities;
  if (!caps?.sampling) return { fact: null };
  if (!context.tools || context.tools.length === 0) return { fact: null };

  const graph = buildCapabilityGraph(context.tools);
  const ingestion: I7IngestionNode[] = [];
  for (const node of graph.nodes) {
    for (const cap of node.capabilities) {
      if (cap.capability !== "ingests-untrusted") continue;
      if (cap.confidence < I7_INGESTION_MIN_CONFIDENCE) continue;
      ingestion.push({
        tool_name: node.name,
        capability: cap.capability,
        confidence: cap.confidence,
      });
      break;
    }
  }
  if (ingestion.length === 0) return { fact: null };
  return {
    fact: {
      sampling_declared: true,
      ingestion_nodes: ingestion,
    },
  };
}
