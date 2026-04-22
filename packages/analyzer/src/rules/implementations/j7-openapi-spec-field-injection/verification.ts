import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { J7Hit } from "./gather.js";

export function stepInspectTemplate(hit: J7Hit): VerificationStep {
  const target: Location = {
    kind: "source",
    file: "<server source>",
    line: hit.line_number,
  };
  return {
    step_type: "inspect-source",
    instruction:
      `At line ${hit.line_number}, inspect the code-generation template. ` +
      `Spec field: ${hit.field_spec.field} (${hit.field_spec.risk_description}). ` +
      `Interpolation kind: ${hit.marker_spec.kind}. Confirm whether the ` +
      `spec field is sanitised / AST-built / escaped before it reaches the ` +
      `generated source.`,
    target,
    expected_observation: hit.line_preview,
  };
}

export function stepTraceSpecOrigin(hit: J7Hit): VerificationStep {
  const target: Location = {
    kind: "source",
    file: "<server source>",
    line: hit.line_number,
  };
  return {
    step_type: "trace-flow",
    instruction:
      "Trace the spec field's origin: is it loaded from a trusted, signed " +
      "registry, or fetched from a URL / read from a CDN cache? If the spec " +
      "source is not integrity-checked, the interpolation is a supply-chain " +
      "injection primitive (CVE-2026-22785 / CVE-2026-23947).",
    target,
    expected_observation:
      "Spec field originates from an unverified source and flows into the " +
      "generator template without sanitisation.",
  };
}
