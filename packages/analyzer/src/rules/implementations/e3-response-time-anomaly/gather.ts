/**
 * E3 evidence gathering — read response_time_ms from connection metadata.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";

export const RESPONSE_TIME_THRESHOLD_MS = 10_000;
export const EXTREME_RESPONSE_TIME_THRESHOLD_MS = 30_000;

export interface LatencyObservation {
  responseTimeMs: number;
  isExtreme: boolean;
  capabilityLocation: Location;
}

export interface E3Gathered {
  observation: LatencyObservation | null;
}

export function gatherE3(context: AnalysisContext): E3Gathered {
  const meta = context.connection_metadata;
  if (!meta) return { observation: null };
  if (meta.response_time_ms <= RESPONSE_TIME_THRESHOLD_MS) return { observation: null };

  return {
    observation: {
      responseTimeMs: meta.response_time_ms,
      isExtreme: meta.response_time_ms > EXTREME_RESPONSE_TIME_THRESHOLD_MS,
      capabilityLocation: {
        kind: "capability",
        capability: "tools",
      },
    },
  };
}
