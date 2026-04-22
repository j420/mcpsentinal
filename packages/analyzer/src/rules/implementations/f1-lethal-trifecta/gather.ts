/**
 * F1 evidence gathering — capability-graph + schema-structural inference.
 *
 * Translates the threat-researcher CHARTER into deterministic facts the
 * sibling `index.ts` turns into Rule Standard v2 findings. This file does
 * NOT construct evidence chains or findings — it returns structured
 * observations: which tool nodes filled each leg of the trifecta, at what
 * confidence, via which signals, and with what companion patterns
 * (command-injection chain / credential-exposure / circular-data-loop)
 * detected in the same graph pass.
 *
 * Wraps the shared `capability-graph.ts` and `schema-inference.ts`
 * analyzers. No regex literals, no string-literal arrays > 5. Semantic
 * vocabulary for the three legs lives in `./data/capability-legs.ts` as
 * typed records.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  buildCapabilityGraph,
  type Capability,
  type CapabilityGraphResult,
  type GraphPattern,
  type ToolNode,
  type WeightedCapability,
} from "../../analyzers/capability-graph.js";
import {
  analyzeToolSet,
  type CrossToolPattern,
} from "../../analyzers/schema-inference.js";
import {
  PRIVATE_DATA_CAPABILITIES,
  UNTRUSTED_CONTENT_CAPABILITIES,
  EXTERNAL_COMMS_CAPABILITIES,
  TRIFECTA_MIN_LEG_CONFIDENCE,
  type LegEntry,
} from "./data/capability-legs.js";

/** A single contribution by a tool node to one of the three trifecta legs. */
export interface LegContribution {
  tool_name: string;
  capability: Capability;
  confidence: number;
  signal_count: number;
  attribution: string;
}

/** The three trifecta legs, each a list of contributing nodes. */
export interface TrifectaLegs {
  private_data: LegContribution[];
  untrusted_content: LegContribution[];
  external_comms: LegContribution[];
}

/** Companion pattern emitted as F2 / F3 / F6 by F1's analyze(). */
export interface CompanionPattern {
  /** Which companion rule this pattern maps to. */
  companion: "F2" | "F3" | "F6";
  /** The underlying capability-graph / schema-inference pattern. */
  pattern: GraphPattern | CrossToolPattern;
  /** The source of the pattern — "graph" for capability-graph, "schema" for schema-inference. */
  origin: "graph" | "schema";
}

/** Everything F1's index.ts needs to build findings. */
export interface F1Gathered {
  /** The raw capability graph result — keeps signal details for chain rationale. */
  graph: CapabilityGraphResult;
  /** Schema-structural analysis result — finer-grained than graph capabilities. */
  schema: ReturnType<typeof analyzeToolSet>;
  /** Whether the three-leg trifecta is present above confidence threshold. */
  trifecta_present: boolean;
  /** Contributing nodes for each leg (empty lists if trifecta not present). */
  legs: TrifectaLegs;
  /** Min of (max-confidence-per-leg) — F1's reported confidence. */
  min_leg_confidence: number;
  /** Companion F2/F3/F6 patterns derived from the same graph pass. */
  companions: CompanionPattern[];
}

/** Gather all F1 inputs from a single analysis context. */
export function gatherF1(context: AnalysisContext): F1Gathered {
  const tools = context.tools ?? [];
  const graph = buildCapabilityGraph(tools);
  const schema = analyzeToolSet(tools);

  const legs = classifyLegs(graph.nodes);
  const trifecta_present =
    legs.private_data.length > 0 &&
    legs.untrusted_content.length > 0 &&
    legs.external_comms.length > 0;

  const min_leg_confidence = trifecta_present
    ? minOfLegMaxes(legs)
    : 0;

  const companions = collectCompanions(graph, schema);

  return {
    graph,
    schema,
    trifecta_present,
    legs,
    min_leg_confidence,
    companions,
  };
}

/** Classify each graph node into at most one leg per capability it carries. */
function classifyLegs(nodes: ToolNode[]): TrifectaLegs {
  const legs: TrifectaLegs = {
    private_data: [],
    untrusted_content: [],
    external_comms: [],
  };

  for (const node of nodes) {
    for (const cap of node.capabilities) {
      if (cap.confidence < TRIFECTA_MIN_LEG_CONFIDENCE) continue;
      const entry = findLegEntry(cap);
      if (!entry) continue;
      const contribution: LegContribution = {
        tool_name: node.name,
        capability: cap.capability,
        confidence: cap.confidence,
        signal_count: cap.signals.length,
        attribution: entry.attribution,
      };
      pushToLeg(legs, entry.leg, contribution);
    }
  }

  return legs;
}

function findLegEntry(cap: WeightedCapability): LegEntry | null {
  const pd = PRIVATE_DATA_CAPABILITIES[cap.capability];
  if (pd) return pd;
  const ut = UNTRUSTED_CONTENT_CAPABILITIES[cap.capability];
  if (ut) return ut;
  const ex = EXTERNAL_COMMS_CAPABILITIES[cap.capability];
  if (ex) return ex;
  return null;
}

function pushToLeg(
  legs: TrifectaLegs,
  which: LegEntry["leg"],
  contribution: LegContribution,
): void {
  if (which === "private_data") legs.private_data.push(contribution);
  else if (which === "untrusted_content") legs.untrusted_content.push(contribution);
  else legs.external_comms.push(contribution);
}

function minOfLegMaxes(legs: TrifectaLegs): number {
  const pd = Math.max(...legs.private_data.map((c) => c.confidence));
  const ut = Math.max(...legs.untrusted_content.map((c) => c.confidence));
  const ex = Math.max(...legs.external_comms.map((c) => c.confidence));
  return Math.min(pd, ut, ex);
}

/**
 * Walk the graph patterns + schema cross-tool patterns and bucket each into
 * the companion rule it maps to:
 *
 *   command_injection_chain / unrestricted_access → F2 (High-Risk Profile)
 *   credential_exposure                           → F3 (Source→Sink)
 *   circular_data_loop                            → F6 (Circular Loop)
 *
 * Exfiltration chains are NOT companions of F1 — they're F7's own
 * signature and emitted by F7's rule class.
 */
function collectCompanions(
  graph: CapabilityGraphResult,
  schema: ReturnType<typeof analyzeToolSet>,
): CompanionPattern[] {
  const companions: CompanionPattern[] = [];

  for (const pattern of graph.patterns) {
    if (pattern.type === "command_injection_chain") {
      companions.push({ companion: "F2", pattern, origin: "graph" });
    } else if (pattern.type === "credential_exposure") {
      companions.push({ companion: "F3", pattern, origin: "graph" });
    } else if (pattern.type === "circular_data_loop") {
      companions.push({ companion: "F6", pattern, origin: "graph" });
    }
  }

  for (const pattern of schema.cross_tool_patterns) {
    if (pattern.type === "unrestricted_access") {
      companions.push({ companion: "F2", pattern, origin: "schema" });
    } else if (pattern.type === "credential_exposure") {
      companions.push({ companion: "F3", pattern, origin: "schema" });
    }
  }

  return companions;
}
