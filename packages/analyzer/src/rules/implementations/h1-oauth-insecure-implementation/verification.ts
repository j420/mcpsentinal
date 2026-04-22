/**
 * H1 verification-step builders — source-kind Location targets for
 * every OAuth pattern. An auditor reads the steps, opens the file at
 * the cited line, and confirms the pattern.
 *
 * No regex, no long string-literal arrays.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { H1Hit } from "./gather.js";

export function stepInspectPattern(hit: H1Hit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this line and confirm the OAuth violation pattern ` +
      `"${hit.entry.pattern_name}". The scanner classified it as ` +
      `${hit.pattern}. Normative citation: ${hit.entry.rfc_citation}.`,
    target: hit.location,
    expected_observation:
      `A code expression matching the ${hit.pattern} shape — for example: ` +
      `${shortExpected(hit)}.`,
  };
}

export function stepInspectTaintedSource(hit: H1Hit): VerificationStep | null {
  if (!hit.sourceLocation || !hit.sourceObserved) return null;
  return {
    step_type: "trace-flow",
    instruction:
      `Open the file at the tainted-source line and confirm the value flows ` +
      `into the OAuth parameter without validation. The expression reads ` +
      `directly from a request-scoped object (${hit.sourceObserved}).`,
    target: hit.sourceLocation,
    expected_observation:
      `Source expression reads from a request-scoped variable (req.body, ` +
      `req.query, req.params, req.headers, ctx.*, context.*).`,
  };
}

export function stepReviewRfcBcp(hit: H1Hit): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Open RFC 9700 (OAuth 2.1 BCP) and locate clause ` +
      `${hit.entry.rfc_citation}. Confirm the observed code is incompatible ` +
      `with the clause's requirement or ban.`,
    target: hit.location,
    expected_observation:
      `The observed code directly violates ${hit.entry.rfc_citation} ` +
      `(${hit.entry.pattern_name}).`,
  };
}

function shortExpected(hit: H1Hit): string {
  switch (hit.pattern) {
    case "implicit-flow-literal":
      return `response_type assigned the literal string "token"`;
    case "ropc-grant-literal":
      return `grant_type assigned the literal string "password"`;
    case "localstorage-token-write":
      return `localStorage.setItem called with a token-suggesting key`;
    case "redirect-uri-from-request":
      return `redirect_uri assigned from req.body / req.query / req.params`;
    case "scope-from-request":
      return `scope assigned from req.body / req.query / req.params`;
    case "state-validation-absence":
      return `a handler that reads req.query.code but does not compare a ` +
        `stored state to req.query.state`;
  }
}
