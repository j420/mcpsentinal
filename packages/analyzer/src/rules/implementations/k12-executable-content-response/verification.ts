import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { ExecSite } from "./gather.js";

export function stepInspectExec(site: ExecSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file and confirm the executable construct classified as ` +
      `\`${site.kind}\` is embedded in a ${site.siteType === "return-statement" ? "returned value" : "response-emitting call argument"}. ` +
      `The client consuming this response will interpret the payload — an AI ` +
      `client treating it as text may render the content in a DOM and execute ` +
      `the embedded primitive.`,
    target: site.location,
    expected_observation:
      `Executable construct \`${site.kind}\` flowing through the response ` +
      `boundary without sanitization.`,
  };
}

export function stepCheckSanitizer(site: ExecSite): VerificationStep {
  const target: Location = site.enclosingFunctionLocation ?? site.location;
  return {
    step_type: "inspect-source",
    instruction:
      site.enclosingHasSanitizer
        ? `A sanitizer call (escapeHtml / sanitize / DOMPurify.sanitize / ` +
          `he.encode / validator.escape / xss.inHTML) was observed in the ` +
          `enclosing function scope. Confirm it acts on the VALUE reaching ` +
          `the response, not on unrelated input — sanitizing one variable is ` +
          `not a mitigation for another.`
        : `Confirm that the enclosing function body contains NO sanitizer ` +
          `call. Candidates inspected: escapeHtml / sanitize / DOMPurify / ` +
          `he.encode / validator.escape / xss.inHTML / textContent / ` +
          `createTextNode. Absence is the compliance gap this rule names.`,
    target,
    expected_observation:
      site.enclosingHasSanitizer
        ? `Sanitizer observed but requires manual confirmation of applicability.`
        : `No sanitizer call in enclosing scope — response carries raw ` +
          `executable content to the client.`,
  };
}
