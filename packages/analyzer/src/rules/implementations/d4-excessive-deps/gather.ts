/**
 * D4 evidence gathering — count the dependency array and decide whether
 * to emit. Deterministic; no heuristics beyond the count.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";

export const EXCESSIVE_THRESHOLD = 50;
export const EXTREME_THRESHOLD = 200;

export interface D4Gathered {
  count: number;
  isExcessive: boolean;
  isExtreme: boolean;
  /** First three names — for the narrative "e.g. a, b, c". Never arrays of > 5. */
  sampleNames: string[];
  manifestLocation: Location;
}

export function gatherD4(context: AnalysisContext): D4Gathered {
  const count = context.dependencies.length;
  const sample: string[] = [];
  for (let i = 0; i < context.dependencies.length && sample.length < 3; i++) {
    const dep = context.dependencies[i];
    if (dep?.name) sample.push(dep.name);
  }

  const manifestLocation: Location = {
    kind: "config",
    file: "package.json",
    json_pointer: "/dependencies",
  };

  return {
    count,
    isExcessive: count > EXCESSIVE_THRESHOLD,
    isExtreme: count > EXTREME_THRESHOLD,
    sampleNames: sample,
    manifestLocation,
  };
}
