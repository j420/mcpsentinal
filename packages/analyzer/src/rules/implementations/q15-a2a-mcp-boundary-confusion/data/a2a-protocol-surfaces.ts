/**
 * Q15 — A2A Protocol Surface Vocabulary.
 *
 * Each Record is ≤5 entries. The gather step iterates keys.
 * Zero regex.
 */

/**
 * A2A Agent Card surface. These identifiers appear on the root
 * AgentCard object that A2A servers expose.
 */
export const A2A_AGENT_CARD: Readonly<Record<string, string>> = {
  AgentCard: "A2A AgentCard root object",
  agentCard: "conventional binding name",
  skills: "AgentCard.skills[] — skill metadata array",
  capabilities: "AgentCard.capabilities[] — scope declaration",
  agents: "discovery result list (plural)",
};

/**
 * A2A TaskResult / Part surface.
 */
export const A2A_PART_SURFACE: Readonly<Record<string, string>> = {
  TextPart: "A2A TextPart — textual content with no MCP policy",
  FilePart: "A2A FilePart — file reference with no MCP policy",
  DataPart: "A2A DataPart — structured blob with no MCP policy",
  parts: "A2A TaskResult.parts[] array",
  TaskResult: "A2A TaskResult root type",
};

/**
 * A2A push-notification surface. Reentry vector.
 */
export const A2A_PUSH_SURFACE: Readonly<Record<string, string>> = {
  pushNotification: "A2A push-notification payload",
  onPush: "push-notification handler",
  pushHandler: "push-notification handler",
  notify: "A2A notify(...) helper",
  subscribePush: "A2A subscribePush(...) helper",
};

/**
 * A2A agent-discovery surface.
 */
export const A2A_DISCOVERY_SURFACE: Readonly<Record<string, string>> = {
  discoverAgents: "A2A discoverAgents(...) helper",
  registerAgent: "A2A registerAgent(...) helper",
  advertise: "A2A advertise(...) helper",
  A2A_URI: "a2a:// URI scheme",
  agentRegistry: "A2A agent registry handle",
};

/**
 * MCP-side sinks that receive A2A-sourced data. A match in the
 * same enclosing function as an A2A surface hit is the core Q15
 * signal.
 */
export const MCP_TOOL_SINKS: Readonly<Record<string, string>> = {
  registerTool: "MCP server.registerTool / registerTools",
  toolDescription: "MCP tool description field setter",
  setDescription: "MCP tool description setter helper",
  callTool: "MCP callTool / tool-invocation sink",
  sendToolResult: "MCP sendToolResult / response sink",
};

/**
 * Sanitizer / content-policy identifier vocabulary. Demotes Q15
 * when observed in enclosing scope.
 */
export const CONTENT_POLICY_IDENTIFIERS: Readonly<Record<string, string>> = {
  sanitize: "generic sanitize() helper",
  enforceContentPolicy: "explicit content-policy enforcement",
  validateA2APart: "A2A-part validator",
  scrubA2A: "A2A-scrubber helper",
  contentPolicy: "content-policy wrapper",
};
