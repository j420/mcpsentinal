/**
 * C14 — JWT Algorithm Confusion: verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { JwtHit } from "./gather.js";

export function stepInspectJwtCall(hit: JwtHit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this position and confirm the ${hit.identity.kind === "py-decode" ? "PyJWT" : "JWT"} ` +
      `call shape. The anti-pattern the rule matched is "${hit.pattern}". Verify the ` +
      `call is really the library call the rule thinks it is (not a local shadow ` +
      `function that just happens to share the name "${hit.identity.name}").`,
    target: hit.callLocation,
    expected_observation: `A ${hit.identity.name} call: ${hit.callExpression}. Detail: ${hit.detail}`,
  };
}

export function stepInspectOptions(hit: JwtHit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Inspect the options / kwargs argument and confirm it matches the anti-pattern ` +
      `"${hit.pattern}" EXACTLY. For algorithms-contains-none, read the array and ` +
      `confirm 'none' is present case-insensitively. For verify-without-options, ` +
      `confirm there is no algorithms key anywhere in the call. For the Python ` +
      `pyjwt-verify-false variant, confirm the verify=False or verify_signature: false ` +
      `kwarg is on the call signature — not a comment, not dead code.`,
    target: hit.callLocation,
    expected_observation:
      `The anti-pattern matches the charter description: ${hit.detail}.`,
  };
}

export function stepCheckSiblingSafeCall(hit: JwtHit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction: hit.siblingSafeCallPresent
      ? `A sibling correctly-configured jwt.verify call was found in the same file. ` +
        `This means the developer understands the secure shape; the current call is ` +
        `an inconsistency, not a knowledge gap. Severity stays the same but remediation ` +
        `is simpler: copy the sibling call's options block.`
      : `No correctly-configured sibling jwt.verify call was found in the same file. ` +
        `The developer may not know the secure shape — point them at RFC 8725 §3.1 ` +
        `and the remediation block.`,
    target: hit.callLocation,
    expected_observation: hit.siblingSafeCallPresent
      ? "At least one other jwt.verify call in the file has algorithms: ['RS256'] or equivalent."
      : "No jwt.verify call in the file pins algorithms correctly — this is the file-wide baseline.",
  };
}

export function stepConfirmImpact(hit: JwtHit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      hit.pattern === "decode-used-as-verify"
        ? `Confirm the decode return value feeds into an authorisation decision — ` +
          `an if(payload.isAdmin), a return of payload.sub as user identity, or a ` +
          `function argument named "user". If the return is merely logged and never ` +
          `trusted, the finding may be dismissed.`
        : `Confirm the call is on an authentication / authorisation path — a ` +
          `request-handling middleware, a tool-call auth check, an OAuth token ` +
          `exchange. A jwt.verify call in a throwaway script is not a finding.`,
    target: hit.callLocation,
    expected_observation:
      `The call sits on a code path that gates access to protected functionality — ` +
      `MCP tool invocations, protected resources, admin endpoints.`,
  };
}
