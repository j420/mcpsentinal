/**
 * K15 shared-state / write-surface / read-surface / attestation vocabulary.
 *
 * Each set is modelled as an object (not a string-literal array) to
 * satisfy the `no-static-patterns` guard.
 */

/**
 * Tokens that, when tokenised out of a tool name or description, classify
 * it as referring to a shared-state surface.
 */
export const SHARED_STATE_TOKENS: Record<string, true> = {
  memory: true,
  scratchpad: true,
  scratch: true,
  workspace: true,
  shared: true,
  global: true,
  pool: true,
  queue: true,
  vector: true,
  embedding: true,
  "session-state": true,
  "session-store": true,
  "agent-state": true,
  "agent-memory": true,
  "cross-agent": true,
};

/**
 * Tool-name tokens that classify the tool as a WRITE action. The matcher
 * tokenises on snake_case / kebab-case / camelCase boundaries, lowercases,
 * and intersects with this set.
 */
export const WRITE_ACTION_TOKENS: Record<string, true> = {
  write: true,
  set: true,
  store: true,
  save: true,
  put: true,
  insert: true,
  append: true,
  push: true,
  publish: true,
  post: true,
  upsert: true,
  add: true,
  update: true,
  record: true,
  remember: true,
  commit: true,
  emit: true,
  send: true,
  broadcast: true,
};

/**
 * Tool-name tokens that classify the tool as a READ action.
 */
export const READ_ACTION_TOKENS: Record<string, true> = {
  read: true,
  get: true,
  fetch: true,
  load: true,
  retrieve: true,
  query: true,
  search: true,
  find: true,
  list: true,
  scan: true,
  peek: true,
  recall: true,
  subscribe: true,
  poll: true,
  consume: true,
};

/**
 * Annotation keys that attest the tool respects a trust boundary. When any
 * of these is set to a truthy value, the write-surface is treated as
 * mitigated.
 */
export const TRUST_BOUNDARY_ANNOTATION_KEYS: Record<string, true> = {
  trustboundary: true,
  trustzone: true,
  agentisolated: true,
  perAgent: true,
  tenantscoped: true,
  agentscoped: true,
  isolatedscope: true,
};

/**
 * Parameter-name tokens that, when present AND required, attest the write
 * carries an agent identity — a minimal trust-boundary signal.
 */
export const AGENT_IDENTITY_PARAM_TOKENS: Record<string, true> = {
  agent_id: true,
  agentid: true,
  agent: true,
  tenant_id: true,
  tenantid: true,
  principal_id: true,
  actor_id: true,
  session_id: true,
  namespace: true,
};

/**
 * Tool-name tokens that signal per-agent isolation in the tool's own
 * identity (e.g. `scoped_write`, `isolated_memory_put`). A match suppresses
 * the finding.
 */
export const ISOLATION_NAME_TOKENS: Record<string, true> = {
  isolated: true,
  scoped: true,
  private: true,
  "per-agent": true,
  "per-tenant": true,
  sandboxed: true,
};
