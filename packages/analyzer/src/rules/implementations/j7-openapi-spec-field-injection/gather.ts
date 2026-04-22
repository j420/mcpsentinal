import type { AnalysisContext } from "../../../engine.js";
import {
  OPENAPI_RISK_FIELDS,
  type OpenApiFieldSpec,
} from "../_shared/protocol-shape-catalogue.js";
import {
  J7_INTERPOLATION_MARKERS,
  type InterpolationTokenSpec,
} from "./data/config.js";

export interface J7Hit {
  field_key: string;
  field_spec: OpenApiFieldSpec;
  marker_key: string;
  marker_spec: InterpolationTokenSpec;
  line_number: number;
  line_preview: string;
}

export interface J7GatherResult {
  hits: J7Hit[];
}

export function gatherJ7(context: AnalysisContext): J7GatherResult {
  const hits: J7Hit[] = [];
  const src = context.source_code ?? "";
  if (!src) return { hits };
  const lines = src.split("\n");

  const lowerLines = lines.map((l) => l.toLowerCase());

  // Require: at least one spec-field reference on the SAME line as an
  // interpolation marker. We want generator-like patterns, not
  // coincidental mentions.
  for (let i = 0; i < lines.length; i++) {
    const lowerLine = lowerLines[i];
    // Fence: ignore lines that are obviously tests / comments.
    if (lowerLine.trim().startsWith("//")) continue;
    if (lowerLine.trim().startsWith("*")) continue;

    for (const [fKey, fSpec] of Object.entries(OPENAPI_RISK_FIELDS)) {
      if (!lowerLine.includes(fSpec.field.toLowerCase())) continue;
      // Require an openapi / spec / swagger neighbourhood token on the
      // same line to avoid matching unrelated property names.
      if (
        !lowerLine.includes("openapi") &&
        !lowerLine.includes("swagger") &&
        !lowerLine.includes("spec")
      ) {
        continue;
      }
      for (const [mKey, mSpec] of Object.entries(J7_INTERPOLATION_MARKERS)) {
        if (!lowerLine.includes(mSpec.token)) continue;
        hits.push({
          field_key: fKey,
          field_spec: fSpec,
          marker_key: mKey,
          marker_spec: mSpec,
          line_number: i + 1,
          line_preview: lines[i].trim().slice(0, 180),
        });
        break; // first marker per line is enough
      }
    }
  }
  return { hits };
}
