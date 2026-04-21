/**
 * K15 gather — multi-agent collusion preconditions.
 *
 * Capability-graph analysis over the tool enumeration. Fires when the
 * server exposes BOTH a write-surface tool and a read-surface tool that
 * target the same shared-state surface AND no machine-readable trust-
 * boundary attestation is present on the write side.
 *
 * Zero regex. All vocabulary in `./data/shared-state-vocabulary.ts`.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  SHARED_STATE_TOKENS,
  WRITE_ACTION_TOKENS,
  READ_ACTION_TOKENS,
  TRUST_BOUNDARY_ANNOTATION_KEYS,
  AGENT_IDENTITY_PARAM_TOKENS,
  ISOLATION_NAME_TOKENS,
} from "./data/shared-state-vocabulary.js";

const SHARED_STATE_SET: ReadonlySet<string> = new Set(
  Object.keys(SHARED_STATE_TOKENS).map((k) => k.toLowerCase()),
);
const WRITE_SET: ReadonlySet<string> = new Set(Object.keys(WRITE_ACTION_TOKENS));
const READ_SET: ReadonlySet<string> = new Set(Object.keys(READ_ACTION_TOKENS));
const TRUST_BOUNDARY_ANNOTATION_SET: ReadonlySet<string> = new Set(
  Object.keys(TRUST_BOUNDARY_ANNOTATION_KEYS).map((k) => k.toLowerCase()),
);
const AGENT_IDENTITY_SET: ReadonlySet<string> = new Set(
  Object.keys(AGENT_IDENTITY_PARAM_TOKENS).map((k) => k.toLowerCase()),
);
const ISOLATION_SET: ReadonlySet<string> = new Set(
  Object.keys(ISOLATION_NAME_TOKENS).map((k) => k.toLowerCase()),
);

// ─── Public types ──────────────────────────────────────────────────────────

export type ActionKind = "write" | "read";

export interface SharedStateToolClassification {
  toolName: string;
  toolLocation: Location; // kind: "tool"
  actions: ActionKind[]; // may contain both (tool name includes both read & write tokens — rare)
  sharedStateTokens: string[]; // tokens from SHARED_STATE_SET matched in name/description
  matchMode: "name" | "description" | "name+description";
  hasTrustBoundaryAnnotation: boolean;
  requiredAgentIdentityParam: string | null; // e.g. "agent_id" when present & required
  hasIsolationNameToken: boolean;
}

export interface ColludingPair {
  writeTool: SharedStateToolClassification;
  readTool: SharedStateToolClassification;
  mitigated: boolean;
  mitigationDetail: string;
  surfaceTokens: string[]; // intersection of shared-state tokens
}

export interface K15Gathered {
  pairs: ColludingPair[];
}

// ─── Entry ─────────────────────────────────────────────────────────────────

export function gatherK15(context: AnalysisContext): K15Gathered {
  if (!context.tools || context.tools.length === 0) return { pairs: [] };

  const classified: SharedStateToolClassification[] = [];
  for (const tool of context.tools) {
    const c = classifyTool(tool);
    if (c !== null) classified.push(c);
  }

  // Build the pair set: writes × reads where the shared-state tokens overlap.
  const pairs: ColludingPair[] = [];
  const writes = classified.filter((c) => c.actions.includes("write"));
  const reads = classified.filter((c) => c.actions.includes("read"));
  for (const w of writes) {
    for (const r of reads) {
      if (w.toolName === r.toolName) continue;
      const surface = intersect(w.sharedStateTokens, r.sharedStateTokens);
      if (surface.length === 0) continue;
      const mitigation = classifyMitigation(w);
      pairs.push({
        writeTool: w,
        readTool: r,
        mitigated: mitigation.mitigated,
        mitigationDetail: mitigation.detail,
        surfaceTokens: surface,
      });
    }
  }

  return { pairs };
}

// ─── Tool classification ───────────────────────────────────────────────────

type ToolShape = AnalysisContext["tools"][number];

function classifyTool(tool: ToolShape): SharedStateToolClassification | null {
  const name = tool.name ?? "";
  const description = tool.description ?? "";
  const nameTokens = tokenize(name);
  const descTokens = tokenize(description);

  // Shared-state token match — at least one.
  const nameSharedTokens = nameTokens.filter((t) => SHARED_STATE_SET.has(t));
  const descSharedTokens = descTokens.filter((t) => SHARED_STATE_SET.has(t));
  if (nameSharedTokens.length === 0 && descSharedTokens.length === 0) {
    return null;
  }

  // Action classification — from tool name.
  const actions: ActionKind[] = [];
  if (nameTokens.some((t) => WRITE_SET.has(t))) actions.push("write");
  if (nameTokens.some((t) => READ_SET.has(t))) actions.push("read");
  if (actions.length === 0) return null;

  const matchMode: "name" | "description" | "name+description" =
    nameSharedTokens.length > 0 && descSharedTokens.length > 0
      ? "name+description"
      : nameSharedTokens.length > 0
        ? "name"
        : "description";

  // Annotation / param / isolation-name checks.
  const hasTrustBoundaryAnnotation = inspectAnnotations(tool);
  const requiredAgentIdentityParam = inspectAgentIdentityParam(tool);
  const hasIsolationNameToken = nameTokens.some((t) => ISOLATION_SET.has(t));

  return {
    toolName: name,
    toolLocation: { kind: "tool", tool_name: name },
    actions,
    sharedStateTokens: dedupe([...nameSharedTokens, ...descSharedTokens]),
    matchMode,
    hasTrustBoundaryAnnotation,
    requiredAgentIdentityParam,
    hasIsolationNameToken,
  };
}

/**
 * Tokenise a string on non-alphanumeric boundaries plus camelCase splits.
 * Lowercases every token.
 */
function tokenize(s: string): string[] {
  if (!s) return [];
  const out: string[] = [];
  let cur = "";
  for (const ch of s) {
    const code = ch.charCodeAt(0);
    const isUpper = code >= 65 && code <= 90;
    const isLower = code >= 97 && code <= 122;
    const isDigit = code >= 48 && code <= 57;
    const isBoundary = !(isUpper || isLower || isDigit);
    if (isBoundary) {
      if (cur.length > 0) out.push(cur.toLowerCase());
      cur = "";
      continue;
    }
    if (isUpper && cur.length > 0) {
      const last = cur.charCodeAt(cur.length - 1);
      const lastIsLower = last >= 97 && last <= 122;
      if (lastIsLower) {
        out.push(cur.toLowerCase());
        cur = "";
      }
    }
    cur += ch;
  }
  if (cur.length > 0) out.push(cur.toLowerCase());
  // Also try a hyphenated-compound form (session-state → session-state kept).
  // We keep joined tokens by scanning the lowered source for each hyphenated
  // shared-state token literal and recording a match.
  const lower = s.toLowerCase();
  for (const hyph of SHARED_STATE_SET) {
    if (hyph.includes("-") && lower.includes(hyph) && !out.includes(hyph)) {
      out.push(hyph);
    }
  }
  return out;
}

function inspectAnnotations(tool: ToolShape): boolean {
  const ann = tool.annotations as Record<string, unknown> | null | undefined;
  if (!ann) return false;
  for (const k of Object.keys(ann)) {
    if (TRUST_BOUNDARY_ANNOTATION_SET.has(k.toLowerCase())) {
      const v = ann[k];
      if (v === true || (typeof v === "string" && v.length > 0)) return true;
    }
  }
  return false;
}

function inspectAgentIdentityParam(tool: ToolShape): string | null {
  const schema = tool.input_schema as Record<string, unknown> | null | undefined;
  if (!schema) return null;
  const props = schema.properties as Record<string, unknown> | undefined;
  if (!props) return null;
  const required = Array.isArray(schema.required) ? (schema.required as string[]) : [];
  for (const pname of Object.keys(props)) {
    const lower = pname.toLowerCase();
    if (AGENT_IDENTITY_SET.has(lower)) {
      if (required.includes(pname)) return pname;
    }
  }
  return null;
}

function classifyMitigation(
  w: SharedStateToolClassification,
): { mitigated: boolean; detail: string } {
  if (w.hasTrustBoundaryAnnotation) {
    return {
      mitigated: true,
      detail: `write tool \`${w.toolName}\` carries a trustBoundary annotation`,
    };
  }
  if (w.requiredAgentIdentityParam !== null) {
    return {
      mitigated: true,
      detail:
        `write tool \`${w.toolName}\` requires parameter ` +
        `\`${w.requiredAgentIdentityParam}\` which attests the actor identity`,
    };
  }
  if (w.hasIsolationNameToken) {
    return {
      mitigated: true,
      detail: `write tool \`${w.toolName}\` carries an isolation signal in its name`,
    };
  }
  return {
    mitigated: false,
    detail:
      `no machine-readable trust-boundary signal (trustBoundary annotation, ` +
      `required agent-identity parameter, or isolation-scoped tool name)`,
  };
}

function intersect(a: string[], b: string[]): string[] {
  const bs = new Set(b);
  return a.filter((x) => bs.has(x));
}

function dedupe(a: string[]): string[] {
  return Array.from(new Set(a));
}
