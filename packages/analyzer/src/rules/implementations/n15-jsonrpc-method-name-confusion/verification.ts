import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { ConfusionSite } from "./gather.js";

export function buildSiteInspectionStep(site: ConfusionSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open line ${site.line}. ${site.label} — this is a ` +
      `method-name-confusion anti-pattern.`,
    target: site.location as Location,
    expected_observation: `Line reads: "${site.line_text}".`,
  };
}

export function buildCanonicalComparisonStep(
  site: ConfusionSite,
): VerificationStep {
  if (site.type === "near_canonical_method" && site.nearest_canonical) {
    return {
      step_type: "compare-baseline",
      instruction:
        `Compare observed handler name "${site.observed_name}" against the ` +
        `canonical spec method "${site.nearest_canonical}". Damerau-` +
        `Levenshtein distance is ${site.levenshtein_distance}. Clients ` +
        `with strict allowlists may miss this variant.`,
      target: site.location as Location,
      expected_observation:
        `Observed name differs from canonical by ≤2 edits — allowlist bypass ` +
        `is likely.`,
    };
  }
  return {
    step_type: "trace-flow",
    instruction:
      `Trace the routing decision: the method-name string propagates from ` +
      `the wire into the handler lookup. Confirm whether the dispatch is ` +
      `bounded to a canonical set.`,
    target: site.location as Location,
    expected_observation:
      `Dispatch consults a map keyed by an attacker-influenceable string.`,
  };
}

export function buildMitigationStep(site: ConfusionSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Verify the server applies an allowlist of canonical MCP method names ` +
      `before dispatch. The correct mitigation: maintain an explicit list ` +
      `(see _shared/mcp-method-catalogue.ts) and reject methods not in it.`,
    target: site.location as Location,
    expected_observation:
      `Method names are normalised (lowercase, trimmed, Unicode-confusable- ` +
      `stripped) and checked against the canonical list before dispatch.`,
  };
}
