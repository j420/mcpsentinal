/**
 * C3 verification-step builders — wrap the shared taint-rule-kit's
 * reusable steps with SSRF-specific sink verb language.
 *
 * No regex, no long string-literal arrays.
 */

import type { VerificationStep } from "../../../evidence.js";
import {
  type TaintFact,
  stepInspectTaintSource,
  stepInspectTaintSink,
  stepTraceTaintPath,
  stepInspectTaintSanitiser,
} from "../_shared/taint-rule-kit/index.js";

export function stepInspectSsrfSource(fact: TaintFact): VerificationStep {
  return stepInspectTaintSource(fact);
}

export function stepInspectSsrfSink(fact: TaintFact): VerificationStep {
  return stepInspectTaintSink(
    fact,
    "an outbound HTTP request (fetch / axios / http.request / https.request / got / requests.get / urllib.request.urlopen / httpx)",
  );
}

export function stepTraceSsrfPath(fact: TaintFact): VerificationStep {
  return stepTraceTaintPath(fact);
}

export function stepInspectSsrfSanitiser(fact: TaintFact): VerificationStep | null {
  return stepInspectTaintSanitiser(fact);
}
