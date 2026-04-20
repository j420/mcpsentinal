/**
 * K17 evidence gathering entry point.
 *
 * Delegates AST work to gather-ast.ts. Returns structured HTTP-call
 * sites with a per-file mitigation summary: whether a global timeout
 * (axios.defaults.timeout, got.extend({ timeout })) was observed, and
 * whether a circuit-breaker dependency is present.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { CIRCUIT_BREAKER_PACKAGES } from "./data/timeout-options.js";
import { gatherFile } from "./gather-ast.js";

const CIRCUIT_BREAKER_SET: ReadonlySet<string> = new Set(Object.keys(CIRCUIT_BREAKER_PACKAGES));

export interface HttpCallSite {
  location: Location;   // kind: "source"
  clientLabel: string;  // "axios.get", "fetch", "got.post"
  observed: string;     // trimmed line
  hasCallTimeoutOption: boolean;
  hasEnclosingAbortSignal: boolean;
}

export interface FileEvidence {
  file: string;
  calls: HttpCallSite[];
  hasGlobalAxiosTimeout: boolean;
  hasGlobalGotTimeout: boolean;
  hasGlobalKyTimeout: boolean;
  isTestFile: boolean;
}

export interface K17Gathered {
  perFile: FileEvidence[];
  hasCircuitBreakerDep: boolean;
  circuitBreakerName: string | null;
}

export function gatherK17(context: AnalysisContext): K17Gathered {
  const perFile: FileEvidence[] = [];
  const files = collectSourceFiles(context);
  for (const [file, text] of files) {
    perFile.push(gatherFile(file, text));
  }

  const breakerDep = context.dependencies.find((d) => CIRCUIT_BREAKER_SET.has(d.name));
  return {
    perFile,
    hasCircuitBreakerDep: breakerDep !== undefined,
    circuitBreakerName: breakerDep ? breakerDep.name : null,
  };
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
