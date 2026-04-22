/**
 * M1 evidence gathering — structural scan of tool metadata for LLM
 * chat-template control tokens.
 *
 * Zero regex literals. Zero string-array > 5. Token catalogue lives in
 * `./data/special-tokens.ts` as a typed record; this file walks the
 * catalogue with `String.prototype.indexOf` against lower-cased metadata.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  SPECIAL_TOKENS,
  RED_TEAM_FENCE_TOKENS,
  type SpecialTokenSpec,
  type TokenClass,
} from "./data/special-tokens.js";

export type MetadataSurface = "tool_name" | "tool_description" | "parameter_description";

export interface TokenSite {
  surface: MetadataSurface;
  tool_name: string;
  parameter_path: string | null;
  token_key: string;
  literal: string;
  kind: TokenClass;
  label: string;
  offset: number;
  observed: string;
  fence_hit: boolean;
  location: Location;
}

export interface M1Gathered {
  sites: TokenSite[];
  /** distinct_kinds — how many token families matched across all surfaces. */
  distinct_kinds: ReadonlySet<TokenClass>;
}

function isBoundaryChar(ch: string): boolean {
  // A conversation-role marker is only a genuine role boundary when it
  // starts at the beginning of the string OR directly after a line break.
  // Prose like "The Human: field" has a space before it — space is NOT
  // a boundary character for this purpose because then ordinary prose
  // would fire constantly. Limit to the tokeniser-relevant start points.
  return ch === "" || ch === "\n" || ch === "\r";
}

function hasFence(text: string): boolean {
  const lc = text.toLowerCase();
  for (const tok of RED_TEAM_FENCE_TOKENS) {
    if (lc.indexOf(tok) !== -1) return true;
  }
  return false;
}

function scanSurface(
  text: string,
  surface: MetadataSurface,
  toolName: string,
  parameterPath: string | null,
): TokenSite[] {
  if (!text) return [];
  const lc = text.toLowerCase();
  const fence = hasFence(lc);
  const sites: TokenSite[] = [];
  for (const [key, spec] of Object.entries(SPECIAL_TOKENS) as Array<
    [string, SpecialTokenSpec]
  >) {
    let from = 0;
    while (from < lc.length) {
      const idx = lc.indexOf(key, from);
      if (idx === -1) break;
      if (spec.boundary_only) {
        const prev = idx === 0 ? "" : lc.charAt(idx - 1);
        if (!isBoundaryChar(prev)) {
          from = idx + key.length;
          continue;
        }
      }
      const location: Location =
        parameterPath !== null
          ? {
              kind: "parameter",
              tool_name: toolName,
              parameter_path: parameterPath,
            }
          : { kind: "tool", tool_name: toolName };
      sites.push({
        surface,
        tool_name: toolName,
        parameter_path: parameterPath,
        token_key: key,
        literal: spec.literal,
        kind: spec.kind,
        label: spec.label,
        offset: idx,
        observed: text.slice(Math.max(0, idx - 4), idx + key.length + 4),
        fence_hit: fence,
        location,
      });
      from = idx + key.length;
    }
  }
  return sites;
}

export function gatherM1(context: AnalysisContext): M1Gathered {
  const sites: TokenSite[] = [];
  const tools = context.tools ?? [];
  for (const tool of tools) {
    if (tool.name) {
      sites.push(...scanSurface(tool.name, "tool_name", tool.name, null));
    }
    if (tool.description) {
      sites.push(
        ...scanSurface(tool.description, "tool_description", tool.name, null),
      );
    }
    const schema = tool.input_schema as
      | { properties?: Record<string, { description?: unknown }> }
      | null
      | undefined;
    const props = schema?.properties;
    if (props && typeof props === "object") {
      for (const [pname, pdef] of Object.entries(props)) {
        const desc = (pdef as { description?: unknown })?.description;
        if (typeof desc === "string") {
          sites.push(
            ...scanSurface(
              desc,
              "parameter_description",
              tool.name,
              `input_schema.properties.${pname}.description`,
            ),
          );
        }
      }
    }
  }

  const distinct_kinds = new Set<TokenClass>();
  for (const s of sites) distinct_kinds.add(s.kind);
  return { sites, distinct_kinds };
}
