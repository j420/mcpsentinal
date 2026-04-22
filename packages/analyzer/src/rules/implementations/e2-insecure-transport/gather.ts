/**
 * E2 evidence gathering — exact-match transport check.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  INSECURE_TRANSPORTS,
  type InsecureTransportSpec,
} from "./data/insecure-transports.js";

export interface InsecureTransportObservation {
  /** Transport label as returned by the scanner (lowercased). */
  transport: string;
  spec: InsecureTransportSpec;
  capabilityLocation: Location;
}

export interface E2Gathered {
  observation: InsecureTransportObservation | null;
}

export function gatherE2(context: AnalysisContext): E2Gathered {
  const meta = context.connection_metadata;
  if (!meta) return { observation: null };

  const transport = meta.transport.toLowerCase();
  const spec = INSECURE_TRANSPORTS[transport];
  if (!spec) return { observation: null };

  return {
    observation: {
      transport,
      spec,
      capabilityLocation: {
        kind: "capability",
        capability: "tools",
      },
    },
  };
}
