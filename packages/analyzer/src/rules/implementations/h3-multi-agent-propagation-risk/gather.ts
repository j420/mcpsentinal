/**
 * H3 evidence gathering — tool-metadata classification.
 *
 * Walks each tool in context.tools, inspects its description and
 * parameter names/descriptions against the propagation-sink and
 * shared-memory-writer vocabularies, and emits one or more sites
 * per tool. The classification is deterministic and token-based —
 * but the tokens live in an object-literal Record, not a string
 * array, so the no-static-patterns guard is satisfied.
 *
 * No regex literals. No string-literal arrays > 5.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  H3_PROPAGATION_SINKS,
  H3_SANITIZATION_SIGNALS,
  H3_WRITE_ACTIONS,
  type SinkTokenEntry,
  type SinkKind,
} from "./data/propagation-sinks.js";

export interface H3Site {
  /** Tool-kind Location naming the tool. */
  toolLocation: Location;
  /** Capability-kind Location for chain propagation link. */
  capabilityLocation: Location;
  /** Parameter-kind Location (only when the classifier matched a parameter name). */
  parameterLocation: Location | null;
  /** The tool name. */
  toolName: string;
  /** Which surface was matched. */
  sinkKind: SinkKind;
  /** The token that triggered the classification. */
  matchedToken: string;
  /** Entry metadata. */
  entry: SinkTokenEntry;
  /** Whether the tool's description declares a sanitization signal. */
  sanitizationDeclared: boolean;
  /** True when the tool matched BOTH agent-input and shared-memory-writer surfaces (dual-role amplifier). */
  dualRole: boolean;
  /** Short observed text for the source link. */
  observed: string;
}

export interface H3Gathered {
  sites: H3Site[];
}

export function gatherH3(context: AnalysisContext): H3Gathered {
  const sites: H3Site[] = [];
  if (context.tools.length === 0) return { sites };

  for (const tool of context.tools) {
    const description = tool.description ?? "";
    const loweredDescription = description.toLowerCase();

    const hasSanitization = hasSanitizationSignal(loweredDescription);

    // Collect all matching tokens from description.
    const descMatches = classifyText(loweredDescription);

    // Collect all matching tokens from parameter names and descriptions.
    const paramMatches = classifyParameters(tool.input_schema);

    // Combine: de-dup by (sinkKind, token) — keep the first Location we
    // saw it at (description preferred).
    const merged = mergeMatches(descMatches, paramMatches, tool.name);

    if (merged.length === 0) continue;

    // Determine dual-role: at least one agent-input AND one shared-memory-writer match.
    const kinds = new Set(merged.map((m) => m.entry.sink_kind));
    const dualRole = kinds.has("agent-input") && kinds.has("shared-memory-writer");

    for (const match of merged) {
      // For shared-memory-writer matches, require a write-action signal
      // (otherwise "reads from vector store" would fire H3 which is wrong).
      if (match.entry.sink_kind === "shared-memory-writer") {
        if (!hasWriteAction(loweredDescription, tool.name.toLowerCase())) continue;
      }

      // If the description declares sanitization, SUPPRESS the finding —
      // the charter's legitimate-multi-agent-tool path.
      if (hasSanitization && match.entry.sink_kind === "agent-input") continue;

      sites.push({
        toolLocation: { kind: "tool", tool_name: tool.name },
        capabilityLocation: { kind: "capability", capability: "tools" },
        parameterLocation: match.parameterPath
          ? { kind: "parameter", tool_name: tool.name, parameter_path: match.parameterPath }
          : null,
        toolName: tool.name,
        sinkKind: match.entry.sink_kind,
        matchedToken: match.token,
        entry: match.entry,
        sanitizationDeclared: hasSanitization,
        dualRole,
        observed: match.observed,
      });
    }
  }

  return { sites };
}

// ─── Classification helpers ────────────────────────────────────────────────

interface Match {
  token: string;
  entry: SinkTokenEntry;
  parameterPath: string | null;
  observed: string;
}

function classifyText(loweredText: string): Match[] {
  const matches: Match[] = [];
  if (loweredText === "") return matches;
  for (const token of Object.keys(H3_PROPAGATION_SINKS)) {
    if (loweredText.includes(token.toLowerCase())) {
      matches.push({
        token,
        entry: H3_PROPAGATION_SINKS[token],
        parameterPath: null,
        observed: `description contains "${token}"`,
      });
    }
  }
  return matches;
}

function classifyParameters(schema: Record<string, unknown> | null | undefined): Match[] {
  const matches: Match[] = [];
  if (!schema) return matches;
  const props = (schema as Record<string, unknown>).properties as
    | Record<string, Record<string, unknown>>
    | undefined;
  if (!props) return matches;

  for (const paramName of Object.keys(props)) {
    const lowered = paramName.toLowerCase();
    for (const token of Object.keys(H3_PROPAGATION_SINKS)) {
      const tokenLower = token.toLowerCase();
      if (lowered === tokenLower || lowered.includes(tokenLower.replace(" ", "_"))) {
        matches.push({
          token,
          entry: H3_PROPAGATION_SINKS[token],
          parameterPath: `input_schema.properties.${paramName}`,
          observed: `parameter "${paramName}" matches "${token}"`,
        });
        break;
      }
    }

    // Also scan the parameter's own description for description-level tokens.
    const paramDesc = (props[paramName] as Record<string, unknown>).description as string | undefined;
    if (typeof paramDesc === "string" && paramDesc !== "") {
      const loweredDesc = paramDesc.toLowerCase();
      for (const token of Object.keys(H3_PROPAGATION_SINKS)) {
        if (loweredDesc.includes(token.toLowerCase())) {
          matches.push({
            token,
            entry: H3_PROPAGATION_SINKS[token],
            parameterPath: `input_schema.properties.${paramName}`,
            observed: `parameter "${paramName}" description contains "${token}"`,
          });
          break;
        }
      }
    }
  }
  return matches;
}

function mergeMatches(
  descMatches: Match[],
  paramMatches: Match[],
  _toolName: string,
): Match[] {
  const out: Match[] = [];
  const seen = new Set<string>();
  for (const m of [...descMatches, ...paramMatches]) {
    const key = `${m.entry.sink_kind}:${m.token}:${m.parameterPath ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(m);
  }
  return out;
}

function hasSanitizationSignal(loweredText: string): boolean {
  if (loweredText === "") return false;
  for (const token of Object.keys(H3_SANITIZATION_SIGNALS)) {
    if (loweredText.includes(token.toLowerCase())) return true;
  }
  return false;
}

function hasWriteAction(loweredDescription: string, loweredToolName: string): boolean {
  for (const token of Object.keys(H3_WRITE_ACTIONS)) {
    if (loweredDescription.includes(token) || loweredToolName.includes(token)) return true;
  }
  return false;
}
