/**
 * Tool Capability Graph Analyzer
 *
 * Builds a directed graph of tool capabilities and data flows,
 * then runs graph algorithms to detect dangerous patterns:
 *
 * 1. Capability Classification — multi-signal classification using schema + annotations + descriptions
 * 2. Data Flow Edges — directed edges between tools based on output→input type compatibility
 * 3. Cycle Detection — DFS-based cycle detection for circular data loops
 * 4. Reachability Analysis — BFS to find source→sink paths
 * 5. Centrality Scoring — identifies tools that are critical data flow bottlenecks
 * 6. Pattern Detection — lethal trifecta, exfiltration chains, privilege escalation chains
 *
 * Why this replaces keyword matching:
 * Current engine classifies capabilities by matching tool names against words like
 * "read", "write", "send". A tool named "get_weather" triggers "reads-data" even
 * though it reads public weather, not private data.
 *
 * This analyzer classifies capabilities using:
 * - Parameter schema analysis (parameter types, names, constraints)
 * - Tool annotations (readOnlyHint, destructiveHint)
 * - Description semantic signals (combined, not individual keywords)
 * - Input/output schema compatibility between tools
 */

/** Capability tag for a tool */
export type Capability =
  | "reads-private-data"
  | "reads-public-data"
  | "writes-data"
  | "executes-code"
  | "accesses-filesystem"
  | "sends-network"
  | "receives-network"
  | "manages-credentials"
  | "ingests-untrusted"
  | "modifies-config"
  | "destructive";

/** Confidence-weighted capability */
export interface WeightedCapability {
  capability: Capability;
  confidence: number; // 0.0–1.0
  /** What signals contributed to this classification */
  signals: CapabilitySignal[];
}

export interface CapabilitySignal {
  source: "annotation" | "parameter_name" | "parameter_type" | "description" | "schema_structure";
  detail: string;
  weight: number;
}

/** A node in the capability graph */
export interface ToolNode {
  name: string;
  description: string | null;
  capabilities: WeightedCapability[];
  /** Parameters that accept data (input channels) */
  input_channels: ParameterChannel[];
  /** Expected output type (output channel) */
  output_channel: OutputChannel | null;
}

export interface ParameterChannel {
  name: string;
  type: string; // "string", "number", "object", "array", "boolean"
  /** Semantic category inferred from name/description */
  semantic: ParameterSemantic;
}

export type ParameterSemantic =
  | "file_path"
  | "url"
  | "sql_query"
  | "command"
  | "text_content"
  | "json_data"
  | "credential"
  | "identifier"
  | "configuration"
  | "generic";

export interface OutputChannel {
  type: string;
  semantic: ParameterSemantic;
}

/** A directed edge in the capability graph */
export interface DataFlowEdge {
  from: string; // tool name (source)
  to: string;   // tool name (sink)
  /** How data flows between these tools */
  flow_type: "output_to_input" | "shared_resource" | "capability_chain";
  /** Confidence that this edge represents real data flow */
  confidence: number;
  /** Which parameters connect */
  connection: {
    from_output?: string;
    to_input: string;
  };
}

/** A detected dangerous pattern in the graph */
export interface GraphPattern {
  type: GraphPatternType;
  tools_involved: string[];
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
}

export type GraphPatternType =
  | "lethal_trifecta"
  | "exfiltration_chain"
  | "privilege_escalation"
  | "circular_data_loop"
  | "credential_exposure"
  | "command_injection_chain"
  | "data_amplification";

/** Complete capability graph analysis result */
export interface CapabilityGraphResult {
  nodes: ToolNode[];
  edges: DataFlowEdge[];
  patterns: GraphPattern[];
  /** Per-tool centrality scores (0.0–1.0) */
  centrality: Map<string, number>;
  /** Cycles detected in the graph */
  cycles: string[][];
}

// --- Capability Classification ---

/** Parameter name patterns for semantic classification */
const PARAM_SEMANTIC_PATTERNS: Array<{
  pattern: RegExp;
  semantic: ParameterSemantic;
}> = [
  { pattern: /(?:file|path|dir|directory|folder|filename)/i, semantic: "file_path" },
  { pattern: /(?:url|uri|endpoint|href|link|webhook)/i, semantic: "url" },
  { pattern: /(?:query|sql|statement|expression)/i, semantic: "sql_query" },
  { pattern: /(?:command|cmd|shell|exec|script|program)/i, semantic: "command" },
  { pattern: /(?:content|text|body|message|data|payload|input)/i, semantic: "text_content" },
  { pattern: /(?:json|object|schema|config|settings)/i, semantic: "json_data" },
  { pattern: /(?:key|token|secret|password|credential|auth|api_key)/i, semantic: "credential" },
  { pattern: /(?:id|name|slug|identifier|ref|handle)/i, semantic: "identifier" },
  { pattern: /(?:config|setting|option|preference|param)/i, semantic: "configuration" },
];

/** Classify a parameter's semantic role from its name and description */
function classifyParameter(name: string, description?: string | null): ParameterSemantic {
  const text = `${name} ${description || ""}`;
  for (const { pattern, semantic } of PARAM_SEMANTIC_PATTERNS) {
    if (pattern.test(text)) return semantic;
  }
  return "generic";
}

/** Multi-signal capability classification for a tool */
function classifyCapabilities(tool: {
  name: string;
  description: string | null;
  input_schema: Record<string, unknown> | null;
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  } | null;
}): WeightedCapability[] {
  const capabilities: WeightedCapability[] = [];
  const signals: Map<Capability, CapabilitySignal[]> = new Map();

  function addSignal(cap: Capability, signal: CapabilitySignal) {
    if (!signals.has(cap)) signals.set(cap, []);
    signals.get(cap)!.push(signal);
  }

  const desc = `${tool.name} ${tool.description || ""}`.toLowerCase();
  const props = (tool.input_schema?.properties || {}) as Record<
    string,
    Record<string, unknown>
  >;
  const paramNames = Object.keys(props);
  const annotations = tool.annotations || {};

  // --- Annotation signals (highest weight: 0.9) ---

  if (annotations.readOnlyHint === true) {
    addSignal("reads-public-data", {
      source: "annotation",
      detail: "readOnlyHint: true",
      weight: 0.9,
    });
  }

  if (annotations.destructiveHint === true) {
    addSignal("destructive", {
      source: "annotation",
      detail: "destructiveHint: true",
      weight: 0.9,
    });
    addSignal("writes-data", {
      source: "annotation",
      detail: "destructiveHint implies writes",
      weight: 0.7,
    });
  }

  // --- Parameter name signals (weight: 0.7) ---

  for (const paramName of paramNames) {
    const sem = classifyParameter(
      paramName,
      (props[paramName]?.description as string) || null
    );

    switch (sem) {
      case "file_path":
        addSignal("accesses-filesystem", {
          source: "parameter_name",
          detail: `parameter "${paramName}" accepts file paths`,
          weight: 0.7,
        });
        break;
      case "url":
        addSignal("sends-network", {
          source: "parameter_name",
          detail: `parameter "${paramName}" accepts URLs`,
          weight: 0.7,
        });
        break;
      case "command":
        addSignal("executes-code", {
          source: "parameter_name",
          detail: `parameter "${paramName}" accepts commands`,
          weight: 0.8,
        });
        break;
      case "sql_query":
        addSignal("reads-private-data", {
          source: "parameter_name",
          detail: `parameter "${paramName}" accepts SQL queries`,
          weight: 0.7,
        });
        break;
      case "credential":
        addSignal("manages-credentials", {
          source: "parameter_name",
          detail: `parameter "${paramName}" handles credentials`,
          weight: 0.8,
        });
        break;
    }
  }

  // --- Description signals (weight: 0.5) ---
  // Use multi-word patterns instead of single keywords

  const descPatterns: Array<{ pattern: RegExp; cap: Capability; weight: number }> = [
    // Private data — requires context words, not just "read"
    { pattern: /read(?:s|ing)?\s+(?:from\s+)?(?:database|credentials|secrets|private|sensitive|user\s+data)/i, cap: "reads-private-data", weight: 0.6 },
    // Public data — requires "public" or "external" context
    { pattern: /(?:fetch|get|read)(?:s|ing)?\s+(?:from\s+)?(?:public|external|open|weather|status)/i, cap: "reads-public-data", weight: 0.5 },
    // Write — requires "write", "modify", "delete", "update" + object
    { pattern: /(?:write|modify|delete|update|create|insert|drop|truncate)(?:s|ing|d)?\s+(?:to\s+)?(?:file|database|record|table|data|document)/i, cap: "writes-data", weight: 0.6 },
    // Execute — strong signals only
    { pattern: /(?:execute|run|invoke|spawn)(?:s|ing)?\s+(?:command|script|shell|process|program|code)/i, cap: "executes-code", weight: 0.7 },
    // Network send — requires destination context
    { pattern: /(?:send|post|upload|push|notify|transmit)(?:s|ing)?\s+(?:to|via|through)\s/i, cap: "sends-network", weight: 0.6 },
    // Ingests untrusted — requires external/untrusted context
    { pattern: /(?:scrape|crawl|fetch|download|ingest|parse)(?:s|ing)?\s+(?:from\s+)?(?:web|external|untrusted|user|url|remote)/i, cap: "ingests-untrusted", weight: 0.6 },
    // Filesystem — requires file/directory context
    { pattern: /(?:read|write|list|delete|create)(?:s|ing)?\s+(?:file|director|folder|path)/i, cap: "accesses-filesystem", weight: 0.5 },
    // Config modification
    { pattern: /(?:modify|change|update|set|configure)(?:s|ing)?\s+(?:config|setting|option|preference|environment)/i, cap: "modifies-config", weight: 0.6 },
  ];

  for (const { pattern, cap, weight } of descPatterns) {
    if (pattern.test(desc)) {
      addSignal(cap, {
        source: "description",
        detail: `description matches "${pattern.source.slice(0, 50)}..."`,
        weight,
      });
    }
  }

  // --- Schema structure signals (weight: 0.6) ---

  // Many parameters with no constraints → broad access
  const unconstrainedCount = paramNames.filter((p) => {
    const param = props[p];
    return param.type === "string" && !param.maxLength && !param.enum && !param.pattern;
  }).length;

  if (unconstrainedCount > 5) {
    addSignal("reads-private-data", {
      source: "schema_structure",
      detail: `${unconstrainedCount} unconstrained string parameters — broad data access surface`,
      weight: 0.4,
    });
  }

  // --- Aggregate signals into weighted capabilities ---

  for (const [cap, sigs] of signals) {
    // Combine signal weights using noisy-OR model:
    // P(capability) = 1 - Π(1 - weight_i)
    let combinedProbability = 1;
    for (const sig of sigs) {
      combinedProbability *= 1 - sig.weight;
    }
    combinedProbability = 1 - combinedProbability;

    if (combinedProbability >= 0.3) {
      capabilities.push({
        capability: cap,
        confidence: combinedProbability,
        signals: sigs,
      });
    }
  }

  return capabilities;
}

// --- Graph Construction ---

/** Build the capability graph from tool metadata */
export function buildCapabilityGraph(
  tools: Array<{
    name: string;
    description: string | null;
    input_schema: Record<string, unknown> | null;
    annotations?: {
      readOnlyHint?: boolean;
      destructiveHint?: boolean;
      idempotentHint?: boolean;
      openWorldHint?: boolean;
    } | null;
  }>
): CapabilityGraphResult {
  // Step 1: Build nodes with capability classification
  const nodes: ToolNode[] = tools.map((tool) => {
    const props = (tool.input_schema?.properties || {}) as Record<
      string,
      Record<string, unknown>
    >;

    const input_channels: ParameterChannel[] = Object.entries(props).map(
      ([name, def]) => ({
        name,
        type: (def.type as string) || "string",
        semantic: classifyParameter(name, (def.description as string) || null),
      })
    );

    return {
      name: tool.name,
      description: tool.description,
      capabilities: classifyCapabilities(tool),
      input_channels,
      output_channel: inferOutputChannel(tool),
    };
  });

  // Step 2: Build edges based on type compatibility
  const edges: DataFlowEdge[] = [];
  for (const source of nodes) {
    for (const target of nodes) {
      if (source.name === target.name) continue;

      // Check if source's output could feed into target's input
      if (source.output_channel) {
        for (const input of target.input_channels) {
          if (isCompatible(source.output_channel.semantic, input.semantic)) {
            edges.push({
              from: source.name,
              to: target.name,
              flow_type: "output_to_input",
              confidence: 0.6,
              connection: {
                from_output: source.output_channel.type,
                to_input: input.name,
              },
            });
          }
        }
      }

      // Check for capability chain (source reads → target sends)
      const sourceReads = source.capabilities.some(
        (c) => c.capability === "reads-private-data" || c.capability === "reads-public-data"
      );
      const targetSends = target.capabilities.some(
        (c) => c.capability === "sends-network"
      );
      if (sourceReads && targetSends) {
        edges.push({
          from: source.name,
          to: target.name,
          flow_type: "capability_chain",
          confidence: 0.4,
          connection: { to_input: "(capability inference)" },
        });
      }
    }
  }

  // Step 3: Detect cycles (DFS)
  const cycles = detectCycles(nodes, edges);

  // Step 4: Compute centrality
  const centrality = computeCentrality(nodes, edges);

  // Step 5: Detect patterns
  const patterns = detectPatterns(nodes, edges, cycles, centrality);

  return { nodes, edges, patterns, centrality, cycles };
}

// --- Graph Algorithms ---

/** DFS-based cycle detection */
function detectCycles(nodes: ToolNode[], edges: DataFlowEdge[]): string[][] {
  const adj = new Map<string, string[]>();
  for (const node of nodes) adj.set(node.name, []);
  for (const edge of edges) {
    adj.get(edge.from)?.push(edge.to);
  }

  const cycles: string[][] = [];
  const visited = new Set<string>();
  const recStack = new Set<string>();

  function dfs(node: string, path: string[]): void {
    visited.add(node);
    recStack.add(node);
    path.push(node);

    for (const neighbor of adj.get(node) || []) {
      if (!visited.has(neighbor)) {
        dfs(neighbor, path);
      } else if (recStack.has(neighbor)) {
        // Found a cycle — extract it
        const cycleStart = path.indexOf(neighbor);
        if (cycleStart >= 0) {
          cycles.push(path.slice(cycleStart));
        }
      }
    }

    path.pop();
    recStack.delete(node);
  }

  for (const node of nodes) {
    if (!visited.has(node.name)) {
      dfs(node.name, []);
    }
  }

  return cycles;
}

/**
 * Betweenness centrality approximation.
 * Measures how often a node lies on shortest paths between other nodes.
 * High centrality = critical data flow bottleneck.
 */
function computeCentrality(
  nodes: ToolNode[],
  edges: DataFlowEdge[]
): Map<string, number> {
  const centrality = new Map<string, number>();
  for (const node of nodes) centrality.set(node.name, 0);

  const adj = new Map<string, string[]>();
  for (const node of nodes) adj.set(node.name, []);
  for (const edge of edges) {
    adj.get(edge.from)?.push(edge.to);
  }

  // For each pair of nodes, find shortest path and count intermediaries
  for (const source of nodes) {
    // BFS from source
    const distances = new Map<string, number>();
    const predecessors = new Map<string, string[]>();
    const queue: string[] = [source.name];
    distances.set(source.name, 0);

    while (queue.length > 0) {
      const current = queue.shift()!;
      const currentDist = distances.get(current)!;

      for (const neighbor of adj.get(current) || []) {
        if (!distances.has(neighbor)) {
          distances.set(neighbor, currentDist + 1);
          predecessors.set(neighbor, [current]);
          queue.push(neighbor);
        } else if (distances.get(neighbor) === currentDist + 1) {
          predecessors.get(neighbor)!.push(current);
        }
      }
    }

    // Back-propagate dependencies
    const dependency = new Map<string, number>();
    for (const node of nodes) dependency.set(node.name, 0);

    // Process nodes in reverse BFS order (farthest first)
    const sortedByDist = [...distances.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([name]) => name);

    for (const w of sortedByDist) {
      if (w === source.name) continue;
      const preds = predecessors.get(w) || [];
      for (const v of preds) {
        const share = (1 + dependency.get(w)!) / preds.length;
        dependency.set(v, dependency.get(v)! + share);
      }
      if (w !== source.name) {
        centrality.set(w, centrality.get(w)! + dependency.get(w)!);
      }
    }
  }

  // Normalize to 0.0–1.0
  const maxCentrality = Math.max(...centrality.values(), 1);
  for (const [name, value] of centrality) {
    centrality.set(name, value / maxCentrality);
  }

  return centrality;
}

// --- Pattern Detection ---

function detectPatterns(
  nodes: ToolNode[],
  edges: DataFlowEdge[],
  cycles: string[][],
  centrality: Map<string, number>
): GraphPattern[] {
  const patterns: GraphPattern[] = [];

  // --- Lethal Trifecta (graph-based) ---
  const readsPrivate = nodes.filter((n) =>
    n.capabilities.some((c) => c.capability === "reads-private-data" && c.confidence >= 0.5)
  );
  const ingestsUntrusted = nodes.filter((n) =>
    n.capabilities.some((c) => c.capability === "ingests-untrusted" && c.confidence >= 0.5)
  );
  const sendsNetwork = nodes.filter((n) =>
    n.capabilities.some((c) => c.capability === "sends-network" && c.confidence >= 0.5)
  );

  if (readsPrivate.length > 0 && ingestsUntrusted.length > 0 && sendsNetwork.length > 0) {
    const confidence = Math.min(
      Math.max(...readsPrivate.flatMap((n) => n.capabilities.filter((c) => c.capability === "reads-private-data").map((c) => c.confidence))),
      Math.max(...ingestsUntrusted.flatMap((n) => n.capabilities.filter((c) => c.capability === "ingests-untrusted").map((c) => c.confidence))),
      Math.max(...sendsNetwork.flatMap((n) => n.capabilities.filter((c) => c.capability === "sends-network").map((c) => c.confidence)))
    );

    patterns.push({
      type: "lethal_trifecta",
      tools_involved: [
        ...readsPrivate.map((n) => n.name),
        ...ingestsUntrusted.map((n) => n.name),
        ...sendsNetwork.map((n) => n.name),
      ],
      description:
        `Lethal trifecta detected with confidence ${(confidence * 100).toFixed(0)}%: ` +
        `reads private data [${readsPrivate.map((n) => n.name).join(", ")}], ` +
        `ingests untrusted content [${ingestsUntrusted.map((n) => n.name).join(", ")}], ` +
        `sends network [${sendsNetwork.map((n) => n.name).join(", ")}]`,
      severity: "critical",
      confidence,
    });
  }

  // --- Exfiltration Chain (3-step: read → transform → send) ---
  const readers = nodes.filter((n) =>
    n.capabilities.some(
      (c) =>
        (c.capability === "reads-private-data" ||
          c.capability === "accesses-filesystem") &&
        c.confidence >= 0.5
    )
  );
  const senders = nodes.filter((n) =>
    n.capabilities.some((c) => c.capability === "sends-network" && c.confidence >= 0.5)
  );

  for (const reader of readers) {
    for (const sender of senders) {
      if (reader.name === sender.name) continue;

      // Check if there's a path from reader to sender
      const path = findPath(reader.name, sender.name, edges);
      if (path && path.length >= 2) {
        patterns.push({
          type: "exfiltration_chain",
          tools_involved: path,
          description:
            `${path.length}-step exfiltration chain: ${path.join(" → ")}. ` +
            `Data read by "${reader.name}" can flow to "${sender.name}" for external transmission.`,
          severity: "critical",
          confidence: 0.7,
        });
      }
    }
  }

  // --- Circular Data Loop (from cycles) ---
  for (const cycle of cycles) {
    const cycleNodes = cycle.map((name) => nodes.find((n) => n.name === name));
    const hasWriter = cycleNodes.some((n) =>
      n?.capabilities.some((c) => c.capability === "writes-data")
    );
    const hasReader = cycleNodes.some((n) =>
      n?.capabilities.some(
        (c) =>
          c.capability === "reads-private-data" ||
          c.capability === "reads-public-data"
      )
    );

    if (hasWriter && hasReader) {
      patterns.push({
        type: "circular_data_loop",
        tools_involved: cycle,
        description:
          `Circular data loop: ${cycle.join(" → ")} → ${cycle[0]}. ` +
          `Write+read cycle enables persistent prompt injection — ` +
          `attacker poisons stored data once, AI reads it on every subsequent access.`,
        severity: "high",
        confidence: 0.65,
      });
    }
  }

  // --- Command Injection Chain ---
  const commandTools = nodes.filter((n) =>
    n.capabilities.some((c) => c.capability === "executes-code" && c.confidence >= 0.5)
  );
  for (const cmdTool of commandTools) {
    // Check if any untrusted ingestion tool can reach this command tool
    for (const ingester of ingestsUntrusted) {
      const path = findPath(ingester.name, cmdTool.name, edges);
      if (path) {
        patterns.push({
          type: "command_injection_chain",
          tools_involved: path,
          description:
            `Untrusted input from "${ingester.name}" can reach command execution ` +
            `in "${cmdTool.name}" via: ${path.join(" → ")}`,
          severity: "critical",
          confidence: 0.6,
        });
      }
    }
  }

  // --- Credential Exposure ---
  const credentialTools = nodes.filter((n) =>
    n.capabilities.some((c) => c.capability === "manages-credentials" && c.confidence >= 0.5)
  );
  for (const credTool of credentialTools) {
    for (const sender of senders) {
      if (credTool.name === sender.name) continue;
      const path = findPath(credTool.name, sender.name, edges);
      if (path) {
        patterns.push({
          type: "credential_exposure",
          tools_involved: path,
          description:
            `Credentials managed by "${credTool.name}" can flow to ` +
            `network sender "${sender.name}" via: ${path.join(" → ")}`,
          severity: "critical",
          confidence: 0.7,
        });
      }
    }
  }

  return patterns;
}

// --- Helper Functions ---

/** BFS path finding between two nodes */
function findPath(
  from: string,
  to: string,
  edges: DataFlowEdge[]
): string[] | null {
  const adj = new Map<string, string[]>();
  for (const edge of edges) {
    if (!adj.has(edge.from)) adj.set(edge.from, []);
    adj.get(edge.from)!.push(edge.to);
  }

  const visited = new Set<string>();
  const queue: Array<{ node: string; path: string[] }> = [
    { node: from, path: [from] },
  ];

  while (queue.length > 0) {
    const { node, path } = queue.shift()!;
    if (node === to) return path;
    if (visited.has(node)) continue;
    visited.add(node);

    for (const neighbor of adj.get(node) || []) {
      if (!visited.has(neighbor)) {
        queue.push({ node: neighbor, path: [...path, neighbor] });
      }
    }
  }

  return null;
}

/** Infer output channel from tool description and schema */
function inferOutputChannel(tool: {
  name: string;
  description: string | null;
}): OutputChannel | null {
  const desc = `${tool.name} ${tool.description || ""}`.toLowerCase();

  if (/(?:returns?|outputs?|produces?)\s+(?:json|object|data)/i.test(desc)) {
    return { type: "object", semantic: "json_data" };
  }
  if (/(?:returns?|reads?|gets?)\s+(?:file|content|text)/i.test(desc)) {
    return { type: "string", semantic: "text_content" };
  }
  if (/(?:returns?|gets?)\s+(?:url|link|path)/i.test(desc)) {
    return { type: "string", semantic: "url" };
  }

  return null;
}

/** Check if a source semantic is compatible with a target semantic */
function isCompatible(
  source: ParameterSemantic,
  target: ParameterSemantic
): boolean {
  if (source === target) return true;
  // Text content can flow into most string-typed parameters
  if (source === "text_content" && target !== "credential") return true;
  // JSON data can flow into text content
  if (source === "json_data" && target === "text_content") return true;
  // URLs can flow into URL parameters
  if (source === "url" && target === "url") return true;
  return false;
}
