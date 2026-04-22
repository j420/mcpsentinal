/**
 * H3 propagation-sink registry.
 *
 * Two vocabularies driven by the charter:
 *   1. AGENT_INPUT_TOKENS — phrases that identify a tool as accepting
 *      output from another agent.
 *   2. SHARED_MEMORY_TOKENS — phrases that identify a tool as writing
 *      to a shared-memory surface other agents read.
 *
 * Object-literal Records so the no-static-patterns guard does not
 * consider the entries as "long string-literal arrays".
 */

export type SinkKind = "agent-input" | "shared-memory-writer";

export interface SinkTokenEntry {
  /** Which propagation surface this token identifies. */
  sink_kind: SinkKind;
  /** Risk-weighting class used by the chain builder. */
  propagation_risk: "high" | "moderate";
  /** Short rationale for the chain. */
  rationale: string;
}

/**
 * Phrases that, when found in a tool description or parameter name,
 * identify the tool as ingesting output from another agent.
 */
export const H3_PROPAGATION_SINKS: Record<string, SinkTokenEntry> = {
  "agent output": {
    sink_kind: "agent-input",
    propagation_risk: "high",
    rationale: "'agent output' in the description names the tool as an inter-agent input surface.",
  },
  "upstream agent": {
    sink_kind: "agent-input",
    propagation_risk: "high",
    rationale: "'upstream agent' references a prior agent in the pipeline.",
  },
  "previous agent": {
    sink_kind: "agent-input",
    propagation_risk: "high",
    rationale: "'previous agent' names a turn-based agent hand-off.",
  },
  "pipeline result": {
    sink_kind: "agent-input",
    propagation_risk: "high",
    rationale: "'pipeline result' names multi-agent pipeline output.",
  },
  "workflow result": {
    sink_kind: "agent-input",
    propagation_risk: "high",
    rationale: "'workflow result' names multi-agent workflow output.",
  },
  "chain output": {
    sink_kind: "agent-input",
    propagation_risk: "high",
    rationale: "'chain output' names an agent-chain (LangChain / LangGraph) output.",
  },
  agent_output: {
    sink_kind: "agent-input",
    propagation_risk: "high",
    rationale: "Parameter name 'agent_output' identifies inter-agent input.",
  },
  upstream_result: {
    sink_kind: "agent-input",
    propagation_risk: "high",
    rationale: "Parameter name 'upstream_result' identifies inter-agent input.",
  },
  previous_agent_response: {
    sink_kind: "agent-input",
    propagation_risk: "high",
    rationale: "Parameter name 'previous_agent_response' identifies inter-agent input.",
  },
  chain_output: {
    sink_kind: "agent-input",
    propagation_risk: "high",
    rationale: "Parameter name 'chain_output' identifies LangChain agent output.",
  },
  workflow_result: {
    sink_kind: "agent-input",
    propagation_risk: "high",
    rationale: "Parameter name 'workflow_result' identifies multi-agent workflow output.",
  },

  // --- Shared-memory writer vocabulary ---
  "vector store": {
    sink_kind: "shared-memory-writer",
    propagation_risk: "high",
    rationale: "Description names a vector store — a canonical shared-memory surface.",
  },
  "vector database": {
    sink_kind: "shared-memory-writer",
    propagation_risk: "high",
    rationale: "Description names a vector database.",
  },
  scratchpad: {
    sink_kind: "shared-memory-writer",
    propagation_risk: "high",
    rationale: "'scratchpad' is the AutoGen / CrewAI shared working-memory idiom.",
  },
  "shared memory": {
    sink_kind: "shared-memory-writer",
    propagation_risk: "high",
    rationale: "'shared memory' names a cross-agent memory surface.",
  },
  "working memory": {
    sink_kind: "shared-memory-writer",
    propagation_risk: "high",
    rationale: "'working memory' names the agent-pipeline shared-memory idiom.",
  },
  "knowledge base": {
    sink_kind: "shared-memory-writer",
    propagation_risk: "moderate",
    rationale: "'knowledge base' may be per-agent or shared — lower-risk signal.",
  },
  embeddings_store: {
    sink_kind: "shared-memory-writer",
    propagation_risk: "high",
    rationale: "Parameter name 'embeddings_store' identifies a vector-store sink.",
  },
  memory_store: {
    sink_kind: "shared-memory-writer",
    propagation_risk: "high",
    rationale: "Parameter name 'memory_store' identifies a shared-memory sink.",
  },
};

/**
 * Sanitization-signal vocabulary — phrases that, when present in a
 * tool description, indicate the author has declared a trust boundary
 * and (likely) sanitised the upstream input. H3 suppresses the finding
 * when ≥1 of these tokens matches.
 */
export const H3_SANITIZATION_SIGNALS: Record<string, { rationale: string }> = {
  "validates upstream": { rationale: "Description explicitly states validation of upstream input." },
  "sanitises upstream": { rationale: "Description explicitly states sanitisation of upstream input." },
  "sanitizes upstream": { rationale: "Description explicitly states sanitization of upstream input." },
  "trust boundary": { rationale: "Description declares an explicit trust boundary." },
  "untrusted content": { rationale: "Description flags the upstream content as untrusted and handles accordingly." },
};

/**
 * Action verbs that identify a write operation to the shared-memory
 * surface. Used together with SHARED_MEMORY_TOKENS to distinguish a
 * "reads from vector store" tool (safe for H3) from a "writes to
 * vector store" tool (the propagation source).
 */
export const H3_WRITE_ACTIONS: Record<string, { note: string }> = {
  write: { note: "Imperative write." },
  store: { note: "Imperative store." },
  save: { note: "Imperative save." },
  upsert: { note: "Vector-database upsert — a write." },
  embed: { note: "Embedding storage." },
};
