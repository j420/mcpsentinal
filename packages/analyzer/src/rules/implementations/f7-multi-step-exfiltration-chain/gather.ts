/**
 * F7 evidence gathering — graph reachability from readers to senders.
 *
 * Wraps the shared `capability-graph.ts` analyzer. Does NOT construct
 * evidence chains — returns the typed chain records `index.ts` consumes.
 *
 * No regex literals, no string-literal arrays > 5. The reader/sender
 * vocabulary lives in `./data/transform-capabilities.ts` as typed records.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  buildCapabilityGraph,
  type Capability,
  type CapabilityGraphResult,
  type GraphPattern,
  type ToolNode,
} from "../../analyzers/capability-graph.js";
import {
  READER_CAPABILITIES,
  SENDER_CAPABILITIES,
  F7_MIN_CHAIN_LENGTH,
  type ChainLegEntry,
} from "./data/transform-capabilities.js";

/** An endpoint of a chain (reader or sender) with the capability that qualifies it. */
export interface ChainEndpoint {
  tool_name: string;
  capability: Capability;
  confidence: number;
  signal_count: number;
  attribution: string;
  /** Centrality score from the capability graph (0..1). */
  centrality: number;
}

/** A concrete path from one reader to one sender. */
export interface ChainPath {
  reader: ChainEndpoint;
  sender: ChainEndpoint;
  /** Full hop list including reader and sender — length ≥ 2. */
  hops: string[];
  /** Transformation hops (excludes reader + sender). */
  transforms: string[];
  /** Pattern's confidence from the capability-graph (base 0.7). */
  base_confidence: number;
}

export interface F7Gathered {
  graph: CapabilityGraphResult;
  chains: ChainPath[];
}

export function gatherF7(context: AnalysisContext): F7Gathered {
  const tools = context.tools ?? [];
  const graph = buildCapabilityGraph(tools);

  const chains = toChainPaths(graph);
  return { graph, chains };
}

/**
 * Walk the graph's `exfiltration_chain` patterns and decorate each with
 * typed reader/sender endpoints. The capability-graph analyzer produces
 * patterns with `tools_involved = [reader, ...hops, sender]` — we promote
 * that into structured endpoints carrying centrality and attribution.
 */
function toChainPaths(graph: CapabilityGraphResult): ChainPath[] {
  const nodeByName = new Map<string, ToolNode>();
  for (const n of graph.nodes) nodeByName.set(n.name, n);

  const chains: ChainPath[] = [];
  const seen = new Set<string>();

  for (const pattern of graph.patterns) {
    if (pattern.type !== "exfiltration_chain") continue;
    if (pattern.tools_involved.length < F7_MIN_CHAIN_LENGTH) continue;

    const firstName = pattern.tools_involved[0];
    const lastName = pattern.tools_involved[pattern.tools_involved.length - 1];
    const firstNode = nodeByName.get(firstName);
    const lastNode = nodeByName.get(lastName);
    if (!firstNode || !lastNode) continue;

    const reader = endpointOfRole(firstNode, "reader", graph.centrality);
    const sender = endpointOfRole(lastNode, "sender", graph.centrality);
    if (!reader || !sender) continue;

    // De-dup: same reader/sender pair already recorded via another exfiltration_chain
    // pattern entry (the graph sometimes yields parallel patterns for the same hop
    // sequence). First-wins.
    const key = `${reader.tool_name}::${sender.tool_name}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const hops = [...pattern.tools_involved];
    const transforms = hops.slice(1, -1);
    chains.push({
      reader,
      sender,
      hops,
      transforms,
      base_confidence: pattern.confidence,
    });
  }

  // Fallback: if the capability-graph did not produce an exfiltration_chain
  // pattern (e.g. because its internal BFS did not find a path) BUT there
  // is at least one reader and one sender, emit a direct 2-hop chain per
  // reader/sender pair. This covers servers where the graph has zero
  // output→input edges but nevertheless carries both legs — the charter's
  // structural argument still holds (the AI is the connecting hop).
  if (chains.length === 0) {
    const readers = collectEndpoints(graph.nodes, READER_CAPABILITIES, "reader", graph.centrality);
    const senders = collectEndpoints(graph.nodes, SENDER_CAPABILITIES, "sender", graph.centrality);
    for (const r of readers) {
      for (const s of senders) {
        if (r.tool_name === s.tool_name) continue;
        const key = `${r.tool_name}::${s.tool_name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        chains.push({
          reader: r,
          sender: s,
          hops: [r.tool_name, s.tool_name],
          transforms: [],
          base_confidence: Math.min(r.confidence, s.confidence),
        });
      }
    }
  }

  return chains;
}

function endpointOfRole(
  node: ToolNode,
  role: "reader" | "sender",
  centrality: Map<string, number>,
): ChainEndpoint | null {
  const registry = role === "reader" ? READER_CAPABILITIES : SENDER_CAPABILITIES;
  let best: {
    cap: Capability;
    confidence: number;
    signals: number;
    entry: ChainLegEntry;
  } | null = null;

  for (const cap of node.capabilities) {
    const entry = registry[cap.capability];
    if (!entry) continue;
    if (cap.confidence < entry.min_confidence) continue;
    if (!best || cap.confidence > best.confidence) {
      best = {
        cap: cap.capability,
        confidence: cap.confidence,
        signals: cap.signals.length,
        entry,
      };
    }
  }

  if (!best) return null;
  return {
    tool_name: node.name,
    capability: best.cap,
    confidence: best.confidence,
    signal_count: best.signals,
    attribution: best.entry.attribution,
    centrality: centrality.get(node.name) ?? 0,
  };
}

function collectEndpoints(
  nodes: ToolNode[],
  registry: Partial<Record<Capability, ChainLegEntry>>,
  role: "reader" | "sender",
  centrality: Map<string, number>,
): ChainEndpoint[] {
  const out: ChainEndpoint[] = [];
  for (const node of nodes) {
    const ep = endpointOfRole(node, role, centrality);
    if (ep) out.push(ep);
  }
  return out;
}

// Exported for index.ts's use in narrative rendering
export type { GraphPattern };
