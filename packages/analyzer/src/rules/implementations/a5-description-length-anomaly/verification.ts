import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { LengthSite } from "./gather.js";

export function stepInspectFullDescription(site: LengthSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "inspect-description",
    instruction:
      `Read the full ${site.length}-character description of tool "${site.tool_name}" ` +
      `from top to bottom. Look particularly at the tail region — recency bias in ` +
      `LLM attention makes that the most effective placement for an injection payload.`,
    target: loc,
    expected_observation:
      `The description is ${site.length} characters long. A legitimate description ` +
      `at this length contains coherent, non-repetitive prose; injection-laden ` +
      `descriptions typically show repetitive filler, abrupt topic shifts, or ` +
      `directive language near the end.`,
  };
}

export function stepCheckForBrevityAlternative(site: LengthSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "compare-baseline",
    instruction:
      `Ask whether this description can be rewritten in < 500 characters without ` +
      `losing essential semantic content. If yes, the existing length is suspicious; ` +
      `if no, document the necessity (e.g. protocol nuance, disambiguation from ` +
      `related tools).`,
    target: loc,
    expected_observation:
      `A lossless rewrite below 500 characters is achievable — the extra ` +
      `${site.length - 500} characters serve no descriptive purpose.`,
  };
}
