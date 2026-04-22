/**
 * E1 evidence gathering — reads context.connection_metadata and decides
 * whether to emit. Silent skip when metadata is null.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";

export interface NoAuthObservation {
  /** Transport the scanner used. */
  transport: string;
  /** Capability location (the tools capability is the gate that was opened). */
  capabilityLocation: Location;
}

export interface E1Gathered {
  observation: NoAuthObservation | null;
}

export function gatherE1(context: AnalysisContext): E1Gathered {
  const meta = context.connection_metadata;
  if (!meta) return { observation: null };
  if (meta.auth_required) return { observation: null };

  const capabilityLocation: Location = {
    kind: "capability",
    capability: "tools",
  };

  return {
    observation: {
      transport: meta.transport,
      capabilityLocation,
    },
  };
}
