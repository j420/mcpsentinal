import type { AnalysisContext } from "../../../engine.js";
import {
  HEALTH_DEBUG_ENDPOINTS,
  type HealthEndpointSpec,
} from "../_shared/protocol-shape-catalogue.js";

export interface J4Hit {
  spec_key: string;
  spec: HealthEndpointSpec;
  line_number: number;
  line_preview: string;
  fence_hit: boolean;
}

export interface J4GatherResult {
  hits: J4Hit[];
}

export function gatherJ4(context: AnalysisContext): J4GatherResult {
  const hits: J4Hit[] = [];
  const src = context.source_code ?? "";
  if (!src) return { hits };
  const lines = src.split("\n");

  for (const [key, spec] of Object.entries(HEALTH_DEBUG_ENDPOINTS)) {
    const path = spec.path.toLowerCase();
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].toLowerCase();
      if (!line.includes(path)) continue;
      const fenceHit = spec.false_positive_fence.some((t) =>
        line.includes(t),
      );
      hits.push({
        spec_key: key,
        spec,
        line_number: i + 1,
        line_preview: lines[i].trim().slice(0, 140),
        fence_hit: fenceHit,
      });
      break;
    }
  }
  return { hits };
}
