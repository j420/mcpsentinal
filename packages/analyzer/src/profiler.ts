/**
 * Server Profiler — Infers what an MCP server actually does from its tools and metadata.
 *
 * Problem: All 177 rules currently run against every server regardless of type.
 * A read-only weather API gets scanned for command injection. A filesystem server
 * gets scanned for OAuth misconfigurations. This produces noise, not signal.
 *
 * Solution: Before running any rules, profile the server to determine:
 * 1. What capabilities it actually has (not keyword matching — schema inference)
 * 2. What attack surface those capabilities create
 * 3. Which threat categories are relevant
 *
 * The profiler examines tools, schemas, annotations, descriptions, and metadata
 * to produce a ServerProfile that downstream systems use for rule filtering,
 * evidence weighting, and threat model selection.
 */

import type { AnalysisContext } from "./engine.js";

// ─── Capability Model ─────────────────────────────────────────────────────────

/**
 * Fine-grained capabilities inferred from tool schemas and metadata.
 * These are more specific than the database CapabilityTag enum —
 * they distinguish "reads private filesystem" from "reads public API data."
 */
export type ServerCapability =
  | "reads-private-data" // Accesses user files, databases, credentials
  | "reads-public-data" // Fetches public APIs, weather, search results
  | "writes-filesystem" // Creates/modifies/deletes files
  | "writes-database" // INSERT/UPDATE/DELETE on databases
  | "executes-code" // Runs arbitrary code, shell commands, scripts
  | "sends-network" // Makes outbound HTTP requests, sends emails/messages
  | "ingests-untrusted" // Reads external content (web scraping, email, user uploads)
  | "manages-credentials" // Handles API keys, tokens, passwords, OAuth
  | "modifies-config" // Writes to config files, environment variables
  | "destructive-ops" // Deletes resources, drops tables, kills processes
  | "cross-agent-comm" // Communicates with other AI agents or shared memory
  | "privileged-system" // Root/admin filesystem access, docker, k8s
  | "user-interaction"; // Requests user input, redirects, elicitation

/** A capability with the evidence that inferred it */
export interface InferredCapability {
  capability: ServerCapability;
  confidence: number; // 0.0–1.0
  /** What evidence led to this inference */
  evidence: CapabilityEvidence[];
}

export interface CapabilityEvidence {
  source:
    | "tool_name"
    | "tool_description"
    | "parameter_name"
    | "parameter_schema"
    | "annotation"
    | "server_description"
    | "resource_uri";
  tool_name: string | null; // null for server-level evidence
  detail: string;
  weight: number; // 0.0–1.0 — how strongly this signal indicates the capability
}

// ─── Attack Surface ───────────────────────────────────────────────────────────

/**
 * Attack surface categories relevant to MCP servers.
 * A server's profile determines which surfaces are exposed.
 */
export type AttackSurface =
  | "code-execution" // Can run arbitrary code on the host
  | "data-exfiltration" // Can read sensitive data AND send it externally
  | "prompt-injection" // Ingests untrusted content that reaches the AI
  | "credential-theft" // Handles credentials that could be stolen
  | "supply-chain" // Has dependencies that could be compromised
  | "privilege-escalation" // Can escalate from limited to broad access
  | "denial-of-service" // Can consume unbounded resources
  | "config-poisoning" // Can modify config to affect future sessions
  | "cross-agent-attack"; // Can propagate attacks to other agents

// ─── Server Profile ───────────────────────────────────────────────────────────

export interface ServerProfile {
  /** Inferred capabilities with evidence */
  capabilities: InferredCapability[];

  /** Attack surfaces this server exposes */
  attack_surfaces: AttackSurface[];

  /** Whether source code is available for deep analysis */
  has_source_code: boolean;

  /** Whether live connection data is available */
  has_connection_data: boolean;

  /** Whether dependency data is available */
  has_dependency_data: boolean;

  /** Tool count — affects consent fatigue analysis */
  tool_count: number;

  /** Data flow pairs: tool A's output can flow to tool B's input */
  data_flow_pairs: DataFlowPair[];

  /** Summary for human review */
  summary: string;
}

export interface DataFlowPair {
  source_tool: string;
  sink_tool: string;
  flow_type: "data-read-to-send" | "ingest-to-execute" | "credential-to-network" | "config-write-read";
}

// ─── Profiler Implementation ──────────────────────────────────────────────────

// Signal patterns for capability inference
// Each pattern has a source type, regex/check, target capability, and confidence weight.
// Patterns are ordered by specificity — more specific patterns first.

interface CapabilityPattern {
  capability: ServerCapability;
  weight: number;
  /** What we're checking */
  check: (tool: AnalysisContext["tools"][0], context: AnalysisContext) => CapabilityEvidence | null;
}

const ANNOTATION_PATTERNS: CapabilityPattern[] = [
  {
    capability: "destructive-ops",
    weight: 0.95,
    check: (tool) => {
      if (tool.annotations?.destructiveHint) {
        return {
          source: "annotation",
          tool_name: tool.name,
          detail: `destructiveHint=true declared by server`,
          weight: 0.95,
        };
      }
      return null;
    },
  },
  {
    capability: "reads-public-data",
    weight: 0.85,
    check: (tool) => {
      if (tool.annotations?.readOnlyHint && !tool.annotations?.openWorldHint) {
        return {
          source: "annotation",
          tool_name: tool.name,
          detail: `readOnlyHint=true, openWorldHint=false — constrained read`,
          weight: 0.85,
        };
      }
      return null;
    },
  },
  {
    capability: "ingests-untrusted",
    weight: 0.80,
    check: (tool) => {
      if (tool.annotations?.openWorldHint) {
        return {
          source: "annotation",
          tool_name: tool.name,
          detail: `openWorldHint=true — tool accepts data from open/untrusted sources`,
          weight: 0.80,
        };
      }
      return null;
    },
  },
];

// Parameter name signals — what a parameter is called reveals what it accepts.
// These are more reliable than description keywords because parameter names
// are functional (code depends on them), not marketing.
const PARAM_NAME_CAPABILITY: Array<{
  pattern: RegExp;
  capability: ServerCapability;
  weight: number;
  detail: string;
}> = [
  { pattern: /^(command|cmd|shell|exec|script|code|expression|eval)$/i, capability: "executes-code", weight: 0.90, detail: "parameter name indicates code execution" },
  { pattern: /^(path|file_?path|filename|directory|dir|folder)$/i, capability: "reads-private-data", weight: 0.70, detail: "parameter name indicates filesystem access" },
  { pattern: /^(sql|query|statement|where_clause)$/i, capability: "writes-database", weight: 0.75, detail: "parameter name indicates database query" },
  { pattern: /^(url|endpoint|uri|href|webhook_?url)$/i, capability: "sends-network", weight: 0.65, detail: "parameter name indicates network access" },
  { pattern: /^(api_?key|token|secret|password|credential|auth|bearer)$/i, capability: "manages-credentials", weight: 0.90, detail: "parameter name indicates credential handling" },
  { pattern: /^(content|body|text|message|payload|data|input)$/i, capability: "ingests-untrusted", weight: 0.40, detail: "parameter name indicates content ingestion (low confidence — generic)" },
  { pattern: /^(recipient|to|email|phone|channel|chat_?id)$/i, capability: "sends-network", weight: 0.75, detail: "parameter name indicates message sending" },
  { pattern: /^(config|setting|env|environment)$/i, capability: "modifies-config", weight: 0.70, detail: "parameter name indicates configuration modification" },
  { pattern: /^(delete|remove|drop|destroy|purge|truncate)$/i, capability: "destructive-ops", weight: 0.85, detail: "parameter name indicates destructive operation" },
];

// Description patterns — checked AFTER parameter/annotation signals.
// Lower weight because descriptions are untrusted text (can be deceptive).
const DESC_CAPABILITY: Array<{
  pattern: RegExp;
  capability: ServerCapability;
  weight: number;
  detail: string;
}> = [
  { pattern: /\b(execut|run|spawn|eval|shell|subprocess|child.process)\w*\b/i, capability: "executes-code", weight: 0.60, detail: "description mentions code execution" },
  { pattern: /\b(read|get|fetch|load|access)\w*\s+(file|directory|folder|path|disk)/i, capability: "reads-private-data", weight: 0.55, detail: "description mentions filesystem reading" },
  { pattern: /\b(write|create|save|update|modify|overwrite)\w*\s+(file|directory|folder)/i, capability: "writes-filesystem", weight: 0.55, detail: "description mentions filesystem writing" },
  { pattern: /\b(send|post|upload|transmit|forward)\w*\s+(email|message|notification|request|data|webhook)/i, capability: "sends-network", weight: 0.55, detail: "description mentions sending data externally" },
  { pattern: /\b(scrape|crawl|fetch|download)\w*\s+(web|page|url|site|html|content)/i, capability: "ingests-untrusted", weight: 0.65, detail: "description mentions web content ingestion" },
  { pattern: /\b(read|get|list|search)\w*\s+(email|inbox|message|ticket|issue|comment|chat)/i, capability: "ingests-untrusted", weight: 0.60, detail: "description mentions reading external messages" },
  { pattern: /\b(delet|remov|drop|truncat|purg|destroy)\w/i, capability: "destructive-ops", weight: 0.55, detail: "description mentions destructive operations" },
  { pattern: /\b(oauth|token|credential|api.key|authenticate|authorize)/i, capability: "manages-credentials", weight: 0.55, detail: "description mentions credential management" },
  { pattern: /\b(docker|container|kubernetes|k8s|helm|pod)\b/i, capability: "privileged-system", weight: 0.50, detail: "description mentions container/orchestration systems" },
  { pattern: /\b(agent|multi.agent|orchestrat|delegat|dispatch)\w*\b/i, capability: "cross-agent-comm", weight: 0.45, detail: "description mentions agent communication" },
  { pattern: /\b(weather|stock|price|quote|exchange.rate|news|time|timezone)\b/i, capability: "reads-public-data", weight: 0.60, detail: "description mentions public data access" },
];

/**
 * Profile an MCP server by analyzing its tools, schemas, annotations, and metadata.
 *
 * Returns a ServerProfile containing:
 * - Capabilities with evidence chains (what the server can do, and how we know)
 * - Attack surfaces (what threat categories are relevant)
 * - Data flow pairs (which tools can chain into dangerous combinations)
 */
export function profileServer(context: AnalysisContext): ServerProfile {
  const capabilityMap = new Map<ServerCapability, InferredCapability>();

  // Pass 1: Annotation signals (highest confidence — server-declared)
  for (const tool of context.tools) {
    for (const pattern of ANNOTATION_PATTERNS) {
      const evidence = pattern.check(tool, context);
      if (evidence) {
        addCapability(capabilityMap, pattern.capability, evidence);
      }
    }
  }

  // Pass 2: Parameter name signals (high confidence — functional, not cosmetic)
  for (const tool of context.tools) {
    const schema = tool.input_schema;
    if (!schema || typeof schema !== "object") continue;
    const properties = (schema as Record<string, unknown>).properties;
    if (!properties || typeof properties !== "object") continue;

    for (const paramName of Object.keys(properties as Record<string, unknown>)) {
      for (const paramPattern of PARAM_NAME_CAPABILITY) {
        if (paramPattern.pattern.test(paramName)) {
          addCapability(capabilityMap, paramPattern.capability, {
            source: "parameter_name",
            tool_name: tool.name,
            detail: `parameter "${paramName}" — ${paramPattern.detail}`,
            weight: paramPattern.weight,
          });
        }
      }
    }
  }

  // Pass 3: Description signals (lower confidence — descriptions are untrusted)
  for (const tool of context.tools) {
    const desc = tool.description;
    if (!desc) continue;

    for (const descPattern of DESC_CAPABILITY) {
      if (descPattern.pattern.test(desc)) {
        addCapability(capabilityMap, descPattern.capability, {
          source: "tool_description",
          tool_name: tool.name,
          detail: `${descPattern.detail}: "${desc.slice(0, 80)}"`,
          weight: descPattern.weight,
        });
      }
    }
  }

  // Pass 4: Server-level signals
  if (context.server.description) {
    for (const descPattern of DESC_CAPABILITY) {
      if (descPattern.pattern.test(context.server.description)) {
        addCapability(capabilityMap, descPattern.capability, {
          source: "server_description",
          tool_name: null,
          detail: `server description — ${descPattern.detail}`,
          weight: descPattern.weight * 0.7, // Server descriptions are broader, less specific
        });
      }
    }
  }

  // Pass 5: Resource URI signals
  if (context.resources) {
    for (const resource of context.resources) {
      if (resource.uri.startsWith("file://")) {
        addCapability(capabilityMap, "reads-private-data", {
          source: "resource_uri",
          tool_name: null,
          detail: `resource URI "${resource.uri}" — file:// scheme indicates filesystem access`,
          weight: 0.80,
        });
      }
    }
  }

  const capabilities = Array.from(capabilityMap.values());

  // Derive attack surfaces from capabilities
  const attack_surfaces = deriveAttackSurfaces(capabilities);

  // Detect data flow pairs
  const data_flow_pairs = detectDataFlowPairs(context.tools, capabilities);

  const summary = buildProfileSummary(capabilities, attack_surfaces, context);

  return {
    capabilities,
    attack_surfaces,
    has_source_code: !!context.source_code && context.source_code.length > 0,
    has_connection_data: !!context.connection_metadata,
    has_dependency_data: context.dependencies.length > 0,
    tool_count: context.tools.length,
    data_flow_pairs,
    summary,
  };
}

// ─── Noisy-OR Aggregation ─────────────────────────────────────────────────────

/**
 * Add a capability evidence signal, using noisy-OR to combine confidences.
 * P(capability) = 1 - ∏(1 - weight_i)
 *
 * Multiple weak signals combine into strong confidence.
 * A tool with param "path" (0.70) + description "reads files" (0.55)
 * = 1 - (0.30 * 0.45) = 0.865 confidence for reads-private-data.
 */
function addCapability(
  map: Map<ServerCapability, InferredCapability>,
  capability: ServerCapability,
  evidence: CapabilityEvidence,
): void {
  const existing = map.get(capability);
  if (existing) {
    existing.evidence.push(evidence);
    // Noisy-OR: P = 1 - ∏(1 - w_i)
    existing.confidence = 1 - existing.evidence.reduce((prod, e) => prod * (1 - e.weight), 1);
  } else {
    map.set(capability, {
      capability,
      confidence: evidence.weight,
      evidence: [evidence],
    });
  }
}

// ─── Attack Surface Derivation ────────────────────────────────────────────────

function deriveAttackSurfaces(capabilities: InferredCapability[]): AttackSurface[] {
  const surfaces: AttackSurface[] = [];
  const has = (cap: ServerCapability, minConfidence = 0.5) =>
    capabilities.some((c) => c.capability === cap && c.confidence >= minConfidence);

  // Code execution — any server that can run code
  if (has("executes-code")) {
    surfaces.push("code-execution");
  }

  // Data exfiltration — can read AND send (the lethal combination)
  if ((has("reads-private-data") || has("manages-credentials")) && has("sends-network")) {
    surfaces.push("data-exfiltration");
  }

  // Prompt injection — ingests untrusted content that the AI processes
  if (has("ingests-untrusted")) {
    surfaces.push("prompt-injection");
  }

  // Credential theft — handles credentials
  if (has("manages-credentials")) {
    surfaces.push("credential-theft");
  }

  // Privilege escalation — limited + code execution or config modification
  if (has("executes-code") && (has("reads-private-data") || has("privileged-system"))) {
    surfaces.push("privilege-escalation");
  }

  // Config poisoning — can write to configs
  if (has("modifies-config")) {
    surfaces.push("config-poisoning");
  }

  // Cross-agent attack surface
  if (has("cross-agent-comm")) {
    surfaces.push("cross-agent-attack");
  }

  // Supply chain — always applicable if dependencies exist (checked later)
  // This is added by the engine based on has_dependency_data

  return surfaces;
}

// ─── Data Flow Pair Detection ─────────────────────────────────────────────────

function detectDataFlowPairs(
  tools: AnalysisContext["tools"],
  capabilities: InferredCapability[],
): DataFlowPair[] {
  const pairs: DataFlowPair[] = [];
  const capMap = new Map(capabilities.map((c) => [c.capability, c]));

  // Find tools that read data vs. tools that send data
  for (const source of tools) {
    for (const sink of tools) {
      if (source.name === sink.name) continue;

      const sourceReads = isToolCapable(source, "reads-private-data", capMap) || isToolCapable(source, "manages-credentials", capMap);
      const sinkSends = isToolCapable(sink, "sends-network", capMap);
      if (sourceReads && sinkSends) {
        pairs.push({
          source_tool: source.name,
          sink_tool: sink.name,
          flow_type: isToolCapable(source, "manages-credentials", capMap) ? "credential-to-network" : "data-read-to-send",
        });
      }

      const sourceIngests = isToolCapable(source, "ingests-untrusted", capMap);
      const sinkExecutes = isToolCapable(sink, "executes-code", capMap);
      if (sourceIngests && sinkExecutes) {
        pairs.push({
          source_tool: source.name,
          sink_tool: sink.name,
          flow_type: "ingest-to-execute",
        });
      }
    }
  }

  return pairs;
}

function isToolCapable(
  tool: AnalysisContext["tools"][0],
  capability: ServerCapability,
  capMap: Map<ServerCapability, InferredCapability>,
): boolean {
  const cap = capMap.get(capability);
  if (!cap || cap.confidence < 0.5) return false;
  // Check if THIS tool contributed evidence to this capability
  return cap.evidence.some((e) => e.tool_name === tool.name);
}

// ─── Profile Summary ──────────────────────────────────────────────────────────

function buildProfileSummary(
  capabilities: InferredCapability[],
  surfaces: AttackSurface[],
  context: AnalysisContext,
): string {
  const highConfCaps = capabilities
    .filter((c) => c.confidence >= 0.5)
    .map((c) => `${c.capability}(${(c.confidence * 100).toFixed(0)}%)`)
    .join(", ");

  const surfaceList = surfaces.join(", ");
  const toolNames = context.tools.map((t) => t.name).join(", ");

  return (
    `Server "${context.server.name}" — ${context.tools.length} tools [${toolNames}]. ` +
    `Capabilities: ${highConfCaps || "none inferred"}. ` +
    `Attack surfaces: ${surfaceList || "minimal"}. ` +
    `Source code: ${context.source_code ? "available" : "unavailable"}. ` +
    `Connection: ${context.connection_metadata ? "live" : "offline"}.`
  );
}
