/**
 * K16 evidence gathering entry point.
 *
 * Delegates AST work to gather-ast.ts. Returns per-file recursion cycles
 * classified by kind (direct / mutual / tool-call / emit) together with
 * depth-guard and cycle-breaker signals. Zero regex.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { gatherFile } from "./gather-ast.js";

/** Kind of recursion edge that closes the cycle. */
export type RecursionEdgeKind =
  | "direct-self-call"
  | "mutual-recursion"
  | "tool-call-roundtrip"
  | "emit-roundtrip";

export interface RecursionCycle {
  /** Location of the call-site closing the cycle (the recursive call). */
  callLocation: Location;
  /** Location of the entry function of the cycle. */
  entryLocation: Location;
  /** Entry function label, e.g. "walk" or "processNode". */
  entryLabel: string;
  /** Function names participating in the cycle (direct + synthesised edges). */
  cycleMembers: readonly string[];
  /** How this cycle edge was discovered. */
  edgeKind: RecursionEdgeKind;
  /** Trimmed text of the recursive call line, ≤200 chars. */
  observedCall: string;
  /** Trimmed text of the entry function header line, ≤200 chars. */
  observedEntry: string;
  /** Whether the entry function declares a parameter in DEPTH_PARAMETER_NAMES. */
  hasDepthParameter: boolean;
  /** Whether the entry function body compares a depth parameter to a
   *  numeric literal or UPPER_SNAKE constant. Presence of the parameter
   *  alone does not set this true. */
  hasDepthComparison: boolean;
  /** Whether the entry function body contains a Set/Map/WeakSet visited
   *  set with a `.has(...)` or `.add(...)` call reachable from the call
   *  site. */
  hasCycleBreaker: boolean;
}

export interface FileEvidence {
  file: string;
  cycles: RecursionCycle[];
  isTestFile: boolean;
}

export interface K16Gathered {
  perFile: FileEvidence[];
}

export function gatherK16(context: AnalysisContext): K16Gathered {
  const perFile: FileEvidence[] = [];
  const files = collectSourceFiles(context);
  for (const [file, text] of files) {
    perFile.push(gatherFile(file, text));
  }
  return { perFile };
}

function collectSourceFiles(context: AnalysisContext): Map<string, string> {
  const out = new Map<string, string>();
  if (context.source_files && context.source_files.size > 0) {
    for (const [k, v] of context.source_files) out.set(k, v);
    return out;
  }
  if (context.source_code) {
    out.set("<concatenated-source>", context.source_code);
  }
  return out;
}
