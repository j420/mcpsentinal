import type { VerificationStep } from "../../../evidence.js";
import type { EncodingSite } from "./gather.js";

export function stepInspectDecode(site: EncodingSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open this line and confirm "${site.decode_name}(...)" is applied to a ` +
      `user-controlled value (req.body / args / query / params / input).`,
    target: site.location,
    expected_observation:
      `Decode call "${site.decode_name}" whose argument is derived from user input.`,
  };
}

export function stepCheckValidator(site: EncodingSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Read the enclosing function from the decode call onwards. Confirm that ` +
      `no validator (validate / sanitize / check / verify / zod / joi / schema) ` +
      `is applied to the DECODED value before it reaches any sensitive sink.`,
    target: site.enclosing_function_location ?? site.location,
    expected_observation: `No post-decode validator in enclosing scope.`,
  };
}

export function stepCheckSink(site: EncodingSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Follow the decoded value to its ultimate sink. If it reaches exec / ` +
      `eval / SQL / file-write, the attack primitive is fully live and the ` +
      `severity escalates to CRITICAL in production review.`,
    target: site.location,
    expected_observation:
      `Decoded user input reaches a dangerous sink (exec / eval / SQL / fs).`,
  };
}
