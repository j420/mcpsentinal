/**
 * F4 evidence gathering — deterministic structural inspection.
 *
 * The threat researcher's charter (CHARTER.md) specifies the edge cases.
 * This file is the engineer's translation into structural queries over
 * `context.tools`. It does NOT produce findings — `index.ts` consumes
 * the gathered facts and builds the evidence chain.
 *
 * No regex literals. No string-literal arrays of length > 5. Spec-field
 * data lives in `./data/spec-fields.ts` as an object-literal registry.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { SPEC_FIELDS, type FieldClass, type SpecFieldEntry } from "./data/spec-fields.js";

/** One evidence site the rule can turn into a finding. */
export interface F4Site {
  /** Tool-kind Location identifying the offending tool. */
  toolLocation: Location; // kind: "tool"
  /** Initialize-kind Location identifying the protocol-level field (unused today; reserved for version checks). */
  initializeLocation: Location | null;
  /** The spec-field class this site documents. */
  fieldClass: FieldClass;
  /** The full spec-field entry — charter metadata the chain builder uses. */
  fieldEntry: SpecFieldEntry;
  /** The tool name exactly as observed (may be empty). */
  rawToolName: string;
}

export interface F4Gathered {
  sites: F4Site[];
}

/**
 * Inspect every tool in `context.tools` and emit one F4Site per spec-field
 * violation. A tool can produce multiple sites (empty name + missing
 * description + missing inputSchema are three distinct findings).
 */
export function gatherF4(context: AnalysisContext): F4Gathered {
  const sites: F4Site[] = [];

  for (const tool of context.tools) {
    const name = tool.name;
    const rawName = typeof name === "string" ? name : "";

    // Empty vs whitespace-only name — structurally distinct classes.
    if (name === null || name === undefined || name === "") {
      sites.push(makeSite(rawName, "tool-name-empty"));
    } else if (name.trim() === "") {
      sites.push(makeSite(rawName, "tool-name-whitespace"));
    }

    // Missing description (null / undefined / empty-after-trim).
    const desc = tool.description;
    if (desc === null || desc === undefined || desc.trim() === "") {
      // Only emit if the tool at least has some name to cite — an entirely
      // nameless tool is already captured by the name-empty finding above.
      sites.push(makeSite(rawName, "tool-description-missing"));
    }

    // Missing inputSchema — null/undefined. We do NOT flag "empty object" —
    // `{}` is a legitimate zero-parameter tool schema.
    const schema = tool.input_schema;
    if (schema === null || schema === undefined) {
      sites.push(makeSite(rawName, "tool-input-schema-missing"));
    }
  }

  return { sites };
}

function makeSite(rawName: string, fieldClass: FieldClass): F4Site {
  const entry = SPEC_FIELDS[fieldClass];
  const toolLocation: Location = {
    kind: "tool",
    tool_name: rawName,
  };
  return {
    toolLocation,
    initializeLocation: null,
    fieldClass,
    fieldEntry: entry,
    rawToolName: rawName,
  };
}
