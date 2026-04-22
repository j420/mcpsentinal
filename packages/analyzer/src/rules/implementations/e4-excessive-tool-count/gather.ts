/**
 * E4 evidence gathering — count tools exposed by the server.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";

export const TOOL_COUNT_THRESHOLD = 50;
export const EXCESSIVE_TOOL_THRESHOLD = 100;

export interface ToolCountObservation {
  count: number;
  isExcessive: boolean;
  capabilityLocation: Location;
}

export interface E4Gathered {
  observation: ToolCountObservation | null;
}

export function gatherE4(context: AnalysisContext): E4Gathered {
  const count = context.tools.length;
  if (count <= TOOL_COUNT_THRESHOLD) return { observation: null };

  return {
    observation: {
      count,
      isExcessive: count > EXCESSIVE_TOOL_THRESHOLD,
      capabilityLocation: {
        kind: "capability",
        capability: "tools",
      },
    },
  };
}
