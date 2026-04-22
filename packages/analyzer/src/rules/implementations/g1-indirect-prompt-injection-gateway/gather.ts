/**
 * G1 evidence gathering — capability-pair inference.
 *
 * Translates the threat-researcher CHARTER into deterministic facts.
 * Wraps the shared `capability-graph.ts` analyzer. This file does NOT
 * build EvidenceChains or RuleResults — it returns typed structured
 * observations the sibling `index.ts` consumes.
 *
 * The inference is structural:
 *
 *   1. Classify every tool's capabilities via buildCapabilityGraph.
 *   2. Collect gateway candidates: tools with a capability in
 *      INGESTION_CAPABILITIES at ≥ min_confidence.
 *   3. Collect sink candidates: tools with a capability in
 *      SINK_CAPABILITIES at ≥ min_confidence.
 *   4. For each gateway, pair with sinks and record whether the
 *      gateway itself declares a content sanitizer (mitigation).
 *
 * Resources (MCP `resources/read` surface) are folded into the gateway
 * collection when present: a resource fetcher is an indirect-injection
 * surface even though its declaration lives in a different protocol
 * object than tools.
 *
 * Zero regex literals. Zero string-literal arrays > 5. Vocabulary lives
 * in `./data/ingestion-capabilities.ts` as typed records.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  buildCapabilityGraph,
  type Capability,
  type CapabilityGraphResult,
  type ToolNode,
  type WeightedCapability,
} from "../../analyzers/capability-graph.js";
import {
  INGESTION_CAPABILITIES,
  INGESTION_KIND_HINTS,
  SINK_CAPABILITIES,
  SANITIZER_PARAM_NAMES,
  type IngestionEntry,
  type IngestionKind,
  type SinkEntry,
  type SinkRole,
} from "./data/ingestion-capabilities.js";

/** A tool classified as an indirect-injection gateway. */
export interface GatewayNode {
  tool_name: string;
  /** The capability tag that qualified it. */
  capability: Capability;
  /** Classifier confidence (0..1). */
  confidence: number;
  /** Number of underlying capability-signal records. */
  signal_count: number;
  /** Ingestion taxonomy tag (web / email / chat / ...). */
  ingestion_kind: IngestionKind;
  /** Trust boundary attribution from the registry. */
  trust_boundary: IngestionEntry["typical_trust_boundary"];
  /** Rationale string for ConfidenceFactor consumers. */
  attribution: string;
  /** Whether the gateway declares a content sanitizer parameter. */
  sanitizer_declared: boolean;
  /** The sanitizer parameter name if one is declared (for mitigation link). */
  sanitizer_parameter: string | null;
  /** `tool` for normal tools, `resource` for MCP resources folded in. */
  origin: "tool" | "resource";
  /** Resource URI when origin is `resource`. */
  resource_uri: string | null;
}

/** A tool classified as a sink the agent can invoke after the gateway. */
export interface SinkNode {
  tool_name: string;
  capability: Capability;
  confidence: number;
  signal_count: number;
  sink_role: SinkRole;
  attribution: string;
}

/** A paired gateway + sink set — one finding emitted per gateway. */
export interface GatewayPair {
  gateway: GatewayNode;
  /** All sinks on the server — full set so the narrative can count them. */
  sinks: SinkNode[];
  /** The canonical sink chosen for the Rule Standard v2 sink link. */
  primary_sink: SinkNode;
}

/** Everything G1's index.ts needs to build findings. */
export interface G1Gathered {
  graph: CapabilityGraphResult;
  /** All gateway candidates on the server. */
  gateways: GatewayNode[];
  /** All sink candidates on the server. */
  sinks: SinkNode[];
  /** Paired gateway/sink findings to emit. Empty when no pair qualifies. */
  pairs: GatewayPair[];
}

export function gatherG1(context: AnalysisContext): G1Gathered {
  const tools = context.tools ?? [];
  const graph = buildCapabilityGraph(tools);

  const gateways = collectGateways(graph.nodes, tools, context);
  const sinks = collectSinks(graph.nodes);

  const pairs: GatewayPair[] = [];
  if (sinks.length > 0) {
    for (const g of gateways) {
      // G1 requires the agent to invoke a SEPARATE tool as the sink after
      // reading the gateway's output. A tool that is simultaneously its
      // own sink (self-pair) does not model the indirect-injection threat
      // — the content never leaves the single tool call. Skip self-only
      // pairs; a finding fires only when the server exposes at least one
      // sink distinct from the gateway.
      const externalSinks = sinks.filter((s) => s.tool_name !== g.tool_name);
      if (externalSinks.length === 0) continue;
      const primary = pickPrimarySink(externalSinks);
      pairs.push({ gateway: g, sinks: externalSinks, primary_sink: primary });
    }
  }

  return { graph, gateways, sinks, pairs };
}

// ─── Gateway collection ────────────────────────────────────────────────────

function collectGateways(
  nodes: ToolNode[],
  toolDefs: AnalysisContext["tools"],
  context: AnalysisContext,
): GatewayNode[] {
  const gateways: GatewayNode[] = [];
  const toolByName = new Map<string, AnalysisContext["tools"][number]>();
  for (const t of toolDefs) toolByName.set(t.name, t);

  for (const node of nodes) {
    const best = pickBestIngestionCap(node.capabilities);
    if (!best) continue;
    const schemaInfo = inspectSanitizer(toolByName.get(node.name));
    gateways.push({
      tool_name: node.name,
      capability: best.cap.capability,
      confidence: best.cap.confidence,
      signal_count: best.cap.signals.length,
      ingestion_kind: inferIngestionKind(node, best.entry.ingestion_kind),
      trust_boundary: best.entry.typical_trust_boundary,
      attribution: best.entry.attribution,
      sanitizer_declared: schemaInfo.present,
      sanitizer_parameter: schemaInfo.name,
      origin: "tool",
      resource_uri: null,
    });
  }

  // MCP resources count as gateways even though they do not flow through
  // the capability-graph analyzer (resources are not tools). Each declared
  // resource is treated as an ingestion node at the ingestion kind's
  // default confidence — the reader has no classifier signals, so the
  // attribution is purely structural (resources are a spec-sanctioned
  // ingestion surface).
  const resources = context.resources ?? [];
  for (const r of resources) {
    gateways.push({
      tool_name: r.name,
      capability: "ingests-untrusted",
      confidence: 0.6,
      signal_count: 0,
      ingestion_kind: "resource_fetch",
      trust_boundary: "external_public",
      attribution:
        `MCP resource "${r.name}" (${r.uri}) is a spec-declared ingestion ` +
        `surface; agent reads occur without per-fetch user consent.`,
      sanitizer_declared: false,
      sanitizer_parameter: null,
      origin: "resource",
      resource_uri: r.uri,
    });
  }

  return gateways;
}

function pickBestIngestionCap(
  caps: WeightedCapability[],
): { cap: WeightedCapability; entry: IngestionEntry } | null {
  let best: { cap: WeightedCapability; entry: IngestionEntry } | null = null;
  for (const c of caps) {
    const entry = INGESTION_CAPABILITIES[c.capability];
    if (!entry) continue;
    if (c.confidence < entry.min_confidence) continue;
    if (!best || c.confidence > best.cap.confidence) {
      best = { cap: c, entry };
    }
  }
  return best;
}

/**
 * Refine the ingestion-kind tag using the classifier's signal details.
 * The registry's default for `ingests-untrusted` is `generic` — we sharpen
 * it if the signal corpus mentions a more specific surface. Look at
 * signal `detail` substrings; this is NOT regex or keyword matching for
 * detection purposes, it is display-only disambiguation (the DETECTION
 * already happened — we just choose a better taxonomy label).
 */
function inferIngestionKind(
  node: ToolNode,
  defaultKind: IngestionKind,
): IngestionKind {
  const nameLower = node.name.toLowerCase();
  const descLower = (node.description ?? "").toLowerCase();
  const combined = `${nameLower} ${descLower}`;
  for (const [kind, hints] of INGESTION_KIND_HINTS) {
    for (const hint of hints) {
      if (combined.indexOf(hint) !== -1) return kind;
    }
  }
  return defaultKind;
}

/**
 * Inspect the tool's input_schema for sanitizer parameter declarations.
 * Present sanitizer → the mitigation link fires present=true, which the
 * EvidenceChainBuilder turns into a -0.30 confidence adjustment.
 */
function inspectSanitizer(
  tool: AnalysisContext["tools"][number] | undefined,
): { present: boolean; name: string | null } {
  if (!tool) return { present: false, name: null };
  const schema = tool.input_schema;
  if (!schema || typeof schema !== "object") return { present: false, name: null };
  const props = (schema as { properties?: Record<string, unknown> }).properties;
  if (!props || typeof props !== "object") return { present: false, name: null };
  for (const key of Object.keys(props)) {
    if (SANITIZER_PARAM_NAMES.indexOf(key) !== -1) {
      return { present: true, name: key };
    }
  }
  return { present: false, name: null };
}

// ─── Sink collection ────────────────────────────────────────────────────────

function collectSinks(nodes: ToolNode[]): SinkNode[] {
  const sinks: SinkNode[] = [];
  for (const node of nodes) {
    const best = pickBestSinkCap(node.capabilities);
    if (!best) continue;
    sinks.push({
      tool_name: node.name,
      capability: best.cap.capability,
      confidence: best.cap.confidence,
      signal_count: best.cap.signals.length,
      sink_role: best.entry.sink_role,
      attribution: best.entry.attribution,
    });
  }
  return sinks;
}

function pickBestSinkCap(
  caps: WeightedCapability[],
): { cap: WeightedCapability; entry: SinkEntry } | null {
  let best: { cap: WeightedCapability; entry: SinkEntry } | null = null;
  for (const c of caps) {
    const entry = SINK_CAPABILITIES[c.capability];
    if (!entry) continue;
    if (c.confidence < entry.min_confidence) continue;
    if (!best || c.confidence > best.cap.confidence) best = { cap: c, entry };
  }
  return best;
}

/**
 * Sink-priority: execute > write > config > network. Code execution is
 * the most severe class of sink; network egress is the most *common*
 * class. We pick the most severe so the finding's narrative shows the
 * worst-case pair.
 */
function pickPrimarySink(sinks: SinkNode[]): SinkNode {
  const order: SinkRole[] = [
    "code_execution",
    "filesystem_write",
    "config_modification",
    "agent_state_write",
    "network_egress",
  ];
  for (const role of order) {
    const match = sinks.find((s) => s.sink_role === role);
    if (match) return match;
  }
  return sinks[0];
}
