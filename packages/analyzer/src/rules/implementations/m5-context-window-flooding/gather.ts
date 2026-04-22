/**
 * M5 evidence gathering — deterministic linguistic + structural schema analysis.
 *
 * No regex literals. No string arrays > 5. The tokeniser is shared in
 * spirit with M4's (word-boundary walker, lowercase, hyphen-preserving).
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  FLOODING_SIGNALS,
  PAGINATION_MITIGATION_TOKENS,
  SCHEMA_MITIGATION_FIELDS,
  UNBOUNDED_SCHEMA_FIELDS,
  DESC_LENGTH_THRESHOLD,
  DESC_LENGTH_WEIGHT,
  type FloodSignal,
  type FloodSignalClass,
} from "./data/flooding-vocabulary.js";

export interface Token {
  readonly value: string;
  readonly start: number;
  readonly end: number;
}

export interface MatchedSignal {
  readonly id: string;
  readonly cls: FloodSignalClass;
  readonly matched_text: string;
  readonly weight: number;
  readonly desc: string;
}

export interface FloodSite {
  readonly tool_name: string;
  readonly description: string;
  readonly location: Location;
  readonly matched_signals: readonly MatchedSignal[];
  readonly has_pagination: boolean;
  readonly has_no_pagination_claim: boolean;
  readonly description_length: number;
  readonly unbounded_schema_field: string | null;
  readonly schema_location: Location | null;
}

// ─── Tokeniser ───────────────────────────────────────────────────────────────

export function tokenise(text: string): Token[] {
  const tokens: Token[] = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    const code = text.charCodeAt(i);
    if (isWordChar(code)) {
      const start = i;
      while (i < n && isWordCharOrHyphen(text.charCodeAt(i))) i++;
      tokens.push({ value: text.slice(start, i).toLowerCase(), start, end: i });
    } else {
      i++;
    }
  }
  return tokens;
}

function isWordChar(c: number): boolean {
  return (
    (c >= 0x30 && c <= 0x39) ||
    (c >= 0x41 && c <= 0x5a) ||
    (c >= 0x61 && c <= 0x7a) ||
    c === 0x5f
  );
}

function isWordCharOrHyphen(c: number): boolean {
  return isWordChar(c) || c === 0x2d;
}

// ─── Signal matching ─────────────────────────────────────────────────────────

function tokenIn(token: string, list: readonly string[]): boolean {
  for (const e of list) if (token === e) return true;
  return false;
}

export function matchSignals(tokens: readonly Token[]): MatchedSignal[] {
  const matches: MatchedSignal[] = [];
  const seenIds = new Set<string>();

  for (const entry of Object.entries(FLOODING_SIGNALS) as Array<[string, FloodSignal]>) {
    const id = entry[0];
    const signal = entry[1];
    if (seenIds.has(id)) continue;

    for (let i = 0; i < tokens.length; i++) {
      const anchor = tokens[i];
      if (!tokenIn(anchor.value, signal.anchor_tokens)) continue;

      if (signal.qualifier_tokens.length === 0) {
        seenIds.add(id);
        matches.push({
          id,
          cls: signal.cls,
          matched_text: anchor.value,
          weight: signal.weight,
          desc: signal.desc,
        });
        break;
      }

      const endIdx = Math.min(tokens.length - 1, i + signal.proximity);
      let matched = false;
      for (let j = i + 1; j <= endIdx; j++) {
        if (tokenIn(tokens[j].value, signal.qualifier_tokens)) {
          matched = true;
          seenIds.add(id);
          matches.push({
            id,
            cls: signal.cls,
            matched_text: `${anchor.value} ... ${tokens[j].value}`,
            weight: signal.weight,
            desc: signal.desc,
          });
          break;
        }
      }
      if (matched) break;
    }
  }
  return matches;
}

// ─── Pagination / mitigation detection ───────────────────────────────────────

export function detectPagination(
  tokens: readonly Token[],
  inputSchema: unknown,
): { present: boolean; noPaginationClaim: boolean } {
  let present = false;
  let noPaginationClaim = false;

  // Description token walk — "no/without X" is aggravation, not mitigation
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    const prev = i > 0 ? tokens[i - 1].value : "";
    const isNegated = prev === "no" || prev === "without";

    if (tok.value === "limit") {
      if (isNegated) noPaginationClaim = true;
      else present = true;
      continue;
    }
    if (tok.value === "pagination") {
      if (isNegated) noPaginationClaim = true;
      else present = true;
      continue;
    }
    if (tokenIn(tok.value, PAGINATION_MITIGATION_TOKENS)) {
      if (isNegated) noPaginationClaim = true;
      else present = true;
    }
  }

  // Schema walk — look for limit/page/offset/cursor/max fields
  if (inputSchema && typeof inputSchema === "object") {
    const schemaStr = schemaFieldNames(inputSchema);
    for (const field of schemaStr) {
      if (tokenIn(field.toLowerCase(), SCHEMA_MITIGATION_FIELDS)) {
        present = true;
      }
    }
  }

  return { present, noPaginationClaim };
}

/** Return all property keys found anywhere in the schema (shallow recursion). */
function schemaFieldNames(obj: unknown, depth = 0): string[] {
  if (depth > 6 || obj === null || typeof obj !== "object") return [];
  const out: string[] = [];
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    out.push(k);
    if (typeof v === "object" && v !== null) {
      out.push(...schemaFieldNames(v, depth + 1));
    }
  }
  return out;
}

// ─── Schema unbounded-flag detection ─────────────────────────────────────────

export function detectUnboundedSchemaField(
  toolName: string,
  inputSchema: unknown,
): { field: string | null; location: Location | null } {
  if (!inputSchema || typeof inputSchema !== "object") {
    return { field: null, location: null };
  }
  const fields = schemaFieldNames(inputSchema);
  for (const f of fields) {
    if (tokenIn(f.toLowerCase(), UNBOUNDED_SCHEMA_FIELDS)) {
      return {
        field: f,
        location: {
          kind: "parameter",
          tool_name: toolName,
          parameter_path: f,
        },
      };
    }
  }
  return { field: null, location: null };
}

// ─── Public gather entrypoint ────────────────────────────────────────────────

export function gatherM5(context: AnalysisContext): FloodSite[] {
  if (!context.tools || context.tools.length === 0) return [];
  const sites: FloodSite[] = [];

  for (const tool of context.tools) {
    const desc = tool.description ?? "";
    const tokens = tokenise(desc);
    const matches = matchSignals(tokens);
    const { present, noPaginationClaim } = detectPagination(tokens, tool.input_schema);
    const unbounded = detectUnboundedSchemaField(tool.name, tool.input_schema);

    const hasDescAnomaly = desc.length > DESC_LENGTH_THRESHOLD;
    const anyFlood =
      matches.length > 0 ||
      unbounded.field !== null ||
      hasDescAnomaly;
    if (!anyFlood) continue;

    // Description-length anomaly as pseudo-signal
    const signals: MatchedSignal[] = [...matches];
    if (hasDescAnomaly) {
      signals.push({
        id: "description-length-anomaly",
        cls: "verbose-output-promise",
        matched_text: `description length ${desc.length} chars`,
        weight: DESC_LENGTH_WEIGHT,
        desc: `description itself exceeds ${DESC_LENGTH_THRESHOLD} chars`,
      });
    }
    if (unbounded.field !== null) {
      signals.push({
        id: "schema-unbounded-flag",
        cls: "unbounded-data-return",
        matched_text: `schema.${unbounded.field}`,
        weight: 0.60,
        desc: `schema contains unbounded-output flag "${unbounded.field}"`,
      });
    }

    sites.push({
      tool_name: tool.name,
      description: desc,
      location: { kind: "tool", tool_name: tool.name },
      matched_signals: signals,
      has_pagination: present,
      has_no_pagination_claim: noPaginationClaim,
      description_length: desc.length,
      unbounded_schema_field: unbounded.field,
      schema_location: unbounded.location,
    });
  }

  return sites;
}
