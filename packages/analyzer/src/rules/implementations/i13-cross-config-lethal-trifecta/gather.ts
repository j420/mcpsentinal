/**
 * I13 evidence gathering — cross-server capability-graph analysis.
 *
 * Inputs: the optional `multi_server_tools` context extension supplied
 * by the scanner when the MCP client config contains multiple servers.
 * When absent (the common per-server scan case), I13 silently returns
 * an empty fact set — honest-refusal per CHARTER edge case 3.
 *
 * Output: the merged capability graph plus per-server contribution
 * mapping (which server provides which leg of the trifecta) so the
 * evidence chain can name specific servers at every link.
 *
 * Zero regex literals. Zero string-literal arrays > 5. Leg vocabulary
 * comes from ./data/capability-legs.ts as typed Records.
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
import type { Location } from "../../location.js";
import {
  PRIVATE_DATA_CAPS,
  UNTRUSTED_CONTENT_CAPS,
  EXTERNAL_COMMS_CAPS,
  LEG_MIN_CONFIDENCE,
  type LegEntry,
} from "./data/capability-legs.js";

// ─── Types ─────────────────────────────────────────────────────────────────

/**
 * One server's entry in the client config. Names the server and its
 * enumerated tool set (the same shape AnalysisContext.tools uses).
 */
export interface ServerEntry {
  server_name: string;
  tools: AnalysisContext["tools"];
}

/** A tool's contribution to one of the three legs, tagged with its server. */
export interface CrossServerLeg {
  server_name: string;
  tool_name: string;
  capability: Capability;
  confidence: number;
  attribution: string;
  /** Structured tool Location for the evidence link. */
  location: Location;
}

export interface CrossServerLegs {
  private_data: CrossServerLeg[];
  untrusted_content: CrossServerLeg[];
  external_comms: CrossServerLeg[];
}

/**
 * Per-server record of which legs this server contributes. Used by the
 * evidence chain to map Server A → [private_data, untrusted_content]
 * etc. so a reviewer can see the distribution at a glance.
 */
export interface ServerContribution {
  server_name: string;
  legs: ("private_data" | "untrusted_content" | "external_comms")[];
  tool_names: string[];
}

export interface I13Gathered {
  /** True when at least one merged-graph trifecta pattern fires. */
  trifecta_present: boolean;
  /** Merged capability graph across all servers in the config. */
  graph: CapabilityGraphResult;
  /** Leg contributions tagged by server. */
  legs: CrossServerLegs;
  /** Per-server contribution summary (≥2 entries required for I13 to fire). */
  contributions: ServerContribution[];
  /** Minimum-of-max-leg-confidences — the finding's confidence base. */
  min_leg_confidence: number;
  /** The raw multi-server input (for chain-link prose). */
  servers: ServerEntry[];
  /** When false, I13 refuses to fire (single-server scope or data absent). */
  applicable: boolean;
}

// ─── Context extension helpers ─────────────────────────────────────────────

/**
 * Read the multi_server_tools extension from an AnalysisContext.
 *
 * The extension is NOT part of the standard AnalysisContext shape —
 * the scanner attaches it when it knows the client config contains
 * ≥2 servers. When absent, I13 is not applicable.
 */
function readMultiServer(context: AnalysisContext): ServerEntry[] | null {
  const bag = context as unknown as Record<string, unknown>;
  const raw = bag.multi_server_tools;
  if (!Array.isArray(raw)) return null;
  const parsed: ServerEntry[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== "object") continue;
    const e = entry as Record<string, unknown>;
    const name = e.server_name;
    const tools = e.tools;
    if (typeof name !== "string" || !Array.isArray(tools)) continue;
    parsed.push({ server_name: name, tools: tools as ServerEntry["tools"] });
  }
  return parsed;
}

// ─── Public API ────────────────────────────────────────────────────────────

/** Gather I13 facts. Returns applicable=false when the context has <2 servers. */
export function gatherI13(context: AnalysisContext): I13Gathered {
  const servers = readMultiServer(context);
  const emptyLegs: CrossServerLegs = {
    private_data: [],
    untrusted_content: [],
    external_comms: [],
  };
  if (!servers || servers.length < 2) {
    return {
      trifecta_present: false,
      graph: { nodes: [], edges: [], patterns: [], centrality: new Map(), cycles: [] },
      legs: emptyLegs,
      contributions: [],
      min_leg_confidence: 0,
      servers: servers ?? [],
      applicable: false,
    };
  }

  // Build a merged graph across all servers. We build a lookup so each
  // tool node can be traced back to the server that provides it.
  const allTools = servers.flatMap((s) => s.tools);
  const graph = buildCapabilityGraph(allTools);

  const toolToServer = new Map<string, string>();
  for (const server of servers) {
    for (const tool of server.tools) toolToServer.set(tool.name, server.server_name);
  }

  const legs = classifyLegs(graph.nodes, toolToServer);
  const trifecta_present =
    legs.private_data.length > 0 &&
    legs.untrusted_content.length > 0 &&
    legs.external_comms.length > 0;

  // Honest refusal: require contributions from at least TWO distinct servers
  // for a cross-config finding. If all three legs come from the same server,
  // that's F1's territory, not I13's.
  const contributions = trifecta_present ? summariseContributions(legs) : [];
  const distinctServers = new Set(contributions.map((c) => c.server_name));
  const crossServer = distinctServers.size >= 2;

  const min_leg_confidence = trifecta_present && crossServer ? minOfLegMaxes(legs) : 0;

  return {
    trifecta_present: trifecta_present && crossServer,
    graph,
    legs,
    contributions,
    min_leg_confidence,
    servers,
    applicable: true,
  };
}

// ─── Leg classification ────────────────────────────────────────────────────

function classifyLegs(nodes: ToolNode[], toolToServer: Map<string, string>): CrossServerLegs {
  const legs: CrossServerLegs = {
    private_data: [],
    untrusted_content: [],
    external_comms: [],
  };

  for (const node of nodes) {
    const serverName = toolToServer.get(node.name) ?? "<unknown>";
    for (const cap of node.capabilities) {
      if (cap.confidence < LEG_MIN_CONFIDENCE) continue;
      const entry = findLegEntry(cap);
      if (!entry) continue;
      const contribution: CrossServerLeg = {
        server_name: serverName,
        tool_name: node.name,
        capability: cap.capability,
        confidence: cap.confidence,
        attribution: entry.attribution,
        location: { kind: "tool", tool_name: node.name },
      };
      pushToLeg(legs, entry.leg, contribution);
    }
  }

  return legs;
}

function findLegEntry(cap: WeightedCapability): LegEntry | null {
  const pd = PRIVATE_DATA_CAPS[cap.capability];
  if (pd) return pd;
  const ut = UNTRUSTED_CONTENT_CAPS[cap.capability];
  if (ut) return ut;
  const ex = EXTERNAL_COMMS_CAPS[cap.capability];
  if (ex) return ex;
  return null;
}

function pushToLeg(
  legs: CrossServerLegs,
  which: LegEntry["leg"],
  contribution: CrossServerLeg,
): void {
  if (which === "private_data") legs.private_data.push(contribution);
  else if (which === "untrusted_content") legs.untrusted_content.push(contribution);
  else legs.external_comms.push(contribution);
}

function minOfLegMaxes(legs: CrossServerLegs): number {
  const pd = Math.max(...legs.private_data.map((c) => c.confidence));
  const ut = Math.max(...legs.untrusted_content.map((c) => c.confidence));
  const ex = Math.max(...legs.external_comms.map((c) => c.confidence));
  return Math.min(pd, ut, ex);
}

// ─── Per-server contribution summary ───────────────────────────────────────

function summariseContributions(legs: CrossServerLegs): ServerContribution[] {
  const byServer = new Map<string, ServerContribution>();

  function record(leg: keyof CrossServerLegs, contrib: CrossServerLeg): void {
    if (!byServer.has(contrib.server_name)) {
      byServer.set(contrib.server_name, {
        server_name: contrib.server_name,
        legs: [],
        tool_names: [],
      });
    }
    const entry = byServer.get(contrib.server_name)!;
    const legKind = leg;
    if (!entry.legs.includes(legKind)) entry.legs.push(legKind);
    if (!entry.tool_names.includes(contrib.tool_name)) entry.tool_names.push(contrib.tool_name);
  }

  for (const c of legs.private_data) record("private_data", c);
  for (const c of legs.untrusted_content) record("untrusted_content", c);
  for (const c of legs.external_comms) record("external_comms", c);

  return Array.from(byServer.values());
}

/** Utility: first graph pattern of type lethal_trifecta, if any. */
export function findLethalTrifectaPattern(graph: CapabilityGraphResult): GraphPattern | null {
  for (const p of graph.patterns) {
    if (p.type === "lethal_trifecta") return p;
  }
  return null;
}
