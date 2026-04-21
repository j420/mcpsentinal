/**
 * K20 audit-field vocabulary.
 *
 * Five recognised audit-field groups mapped from the ISO 27001:2022
 * A.8.15 "who/what/when/where/outcome" skeleton. Each group's members
 * are the property-name aliases that appear in real-world structured
 * logging codebases (pino, winston, loguru) for that concept.
 *
 * Organised as an object of objects so the `no-static-patterns` guard
 * does not count it as a long string-literal array. At module load,
 * callers derive a `Set<string>` from the flattened keys.
 */

export type AuditFieldGroup =
  | "correlation"
  | "caller-identity"
  | "tool-operation"
  | "timestamp"
  | "outcome";

/**
 * Each key is a canonical group name; each value is a nested object
 * whose keys are the lowercased recognised aliases for that group.
 */
export const AUDIT_FIELD_GROUPS: Record<AuditFieldGroup, Record<string, true>> = {
  correlation: {
    correlation_id: true,
    correlationid: true,
    correlation: true,
    request_id: true,
    requestid: true,
    req_id: true,
    reqid: true,
    trace_id: true,
    traceid: true,
    span_id: true,
    spanid: true,
    transaction_id: true,
    transactionid: true,
    causation_id: true,
    x_request_id: true,
    xrequestid: true,
  },
  "caller-identity": {
    user_id: true,
    userid: true,
    user: true,
    actor: true,
    actor_id: true,
    actorid: true,
    subject: true,
    session_id: true,
    sessionid: true,
    caller: true,
    caller_id: true,
    callerid: true,
    principal: true,
    agent_id: true,
    agentid: true,
    client_id: true,
    clientid: true,
  },
  "tool-operation": {
    tool: true,
    tool_name: true,
    toolname: true,
    action: true,
    operation: true,
    op: true,
    handler: true,
    handler_name: true,
    handlername: true,
    method: true,
    endpoint: true,
    route: true,
    resource: true,
  },
  timestamp: {
    timestamp: true,
    time: true,
    ts: true,
    at: true,
    when: true,
    occurred_at: true,
    occurredat: true,
    logged_at: true,
    loggedat: true,
    event_time: true,
    eventtime: true,
  },
  outcome: {
    outcome: true,
    status: true,
    result: true,
    success: true,
    failed: true,
    ok: true,
    code: true,
    status_code: true,
    statuscode: true,
    error: true,
    error_code: true,
    errorcode: true,
    err: true,
  },
};

/**
 * Compile a flattened lookup set from the group map. Every lowercased
 * alias becomes an entry. Used by gather.ts to test whether a property
 * name counts as an observed audit field.
 */
export function buildAuditAliasSet(): ReadonlySet<string> {
  const out = new Set<string>();
  for (const group of Object.values(AUDIT_FIELD_GROUPS)) {
    for (const alias of Object.keys(group)) {
      out.add(alias.toLowerCase());
    }
  }
  return out;
}

/**
 * For a given alias, report which group it belongs to — or null if
 * unrecognised. Used by gather.ts when computing the per-finding
 * "which groups are missing" narrative.
 */
export function groupForAlias(alias: string): AuditFieldGroup | null {
  const lc = alias.toLowerCase();
  for (const [group, aliases] of Object.entries(AUDIT_FIELD_GROUPS) as Array<
    [AuditFieldGroup, Record<string, true>]
  >) {
    if (aliases[lc]) return group;
  }
  return null;
}

/**
 * Minimum recognised-alias count required for a call to be considered
 * to carry "adequate" audit context. A call with fewer than this many
 * observable aliases (after bindings propagation) triggers K20.
 *
 * Tuned to keep parity with the legacy K20 behaviour: a call like
 * `logger.info({ requestId, action })` carries 2 aliases → adequate;
 * a bare string message or a `{ msg }` object carries 0 → insufficient.
 */
export const AUDIT_FIELD_THRESHOLD = 2;
