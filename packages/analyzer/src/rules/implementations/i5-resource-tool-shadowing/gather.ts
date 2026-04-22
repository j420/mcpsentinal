/**
 * I5 gather — detect case- and separator-normalised name collisions
 * between resources and tools on the same server. Cross-references
 * the shared COMMON_TOOL_NAMES table for destructive-by-convention
 * tagging.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  COMMON_TOOL_NAMES,
  type CommonToolNameSpec,
} from "../_shared/protocol-shape-catalogue.js";

export interface I5Fact {
  resource_name: string;
  resource_uri: string;
  tool_name: string;
  match_kind: "exact" | "case-normalised" | "separator-normalised" | "prefix";
  common_tool_hit: CommonToolNameSpec | null;
}

export interface I5GatherResult {
  facts: I5Fact[];
}

export function gatherI5(context: AnalysisContext): I5GatherResult {
  const facts: I5Fact[] = [];
  const resources = context.resources;
  if (!resources || resources.length === 0) return { facts };
  if (!context.tools || context.tools.length === 0) return { facts };

  const toolNames = context.tools.map((t) => t.name);
  const normalisedToolMap = new Map<string, string>();
  for (const name of toolNames) {
    normalisedToolMap.set(normalise(name), name);
  }

  for (const resource of resources) {
    const rName = resource.name;
    if (!rName) continue;
    const rNorm = normalise(rName);

    for (const tool of toolNames) {
      const tNorm = normalise(tool);
      if (rNorm === tNorm) {
        const matchKind: I5Fact["match_kind"] =
          rName === tool
            ? "exact"
            : rName.toLowerCase() === tool.toLowerCase()
              ? "case-normalised"
              : "separator-normalised";
        facts.push({
          resource_name: rName,
          resource_uri: resource.uri,
          tool_name: tool,
          match_kind: matchKind,
          common_tool_hit: lookupCommon(tNorm),
        });
        continue;
      }
      // Prefix collision: resource name starts with tool name + separator
      // OR tool name starts with resource name + separator.
      if (isPrefixCollision(rNorm, tNorm)) {
        facts.push({
          resource_name: rName,
          resource_uri: resource.uri,
          tool_name: tool,
          match_kind: "prefix",
          common_tool_hit: lookupCommon(tNorm),
        });
      }
    }
  }
  return { facts };
}

function normalise(name: string): string {
  // Lowercase and collapse runs of [-, _, space] into a single underscore.
  // Done character-by-character to avoid regex literals in rule code.
  const lowered = name.toLowerCase();
  let out = "";
  let inRun = false;
  for (let i = 0; i < lowered.length; i++) {
    const c = lowered[i];
    if (c === "-" || c === "_" || c === " " || c === "\t") {
      if (!inRun) {
        out += "_";
        inRun = true;
      }
    } else {
      out += c;
      inRun = false;
    }
  }
  return out;
}

function isPrefixCollision(a: string, b: string): boolean {
  if (a === b) return false;
  const shorter = a.length < b.length ? a : b;
  const longer = a.length < b.length ? b : a;
  if (!longer.startsWith(shorter)) return false;
  const next = longer.charAt(shorter.length);
  return next === "_";
}

function lookupCommon(normalised: string): CommonToolNameSpec | null {
  for (const spec of Object.values(COMMON_TOOL_NAMES)) {
    if (normalise(spec.tool_name) === normalised) return spec;
  }
  return null;
}
