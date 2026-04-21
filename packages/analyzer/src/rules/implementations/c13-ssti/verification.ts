/**
 * C13 verification-step builders — wrap the shared kit helpers with
 * SSTI-specific sink verb language.
 */

import type { VerificationStep } from "../../../evidence.js";
import {
  type TaintFact,
  stepInspectTaintSource,
  stepInspectTaintSink,
  stepTraceTaintPath,
  stepInspectTaintSanitiser,
} from "../_shared/taint-rule-kit/index.js";

export function stepInspectTemplateSource(fact: TaintFact): VerificationStep {
  return stepInspectTaintSource(fact);
}

export function stepInspectTemplateSink(fact: TaintFact): VerificationStep {
  return stepInspectTaintSink(
    fact,
    "a template-engine compile / render / from_string call that treats its first argument as TEMPLATE SOURCE",
  );
}

export function stepTraceTemplatePath(fact: TaintFact): VerificationStep {
  return stepTraceTaintPath(fact);
}

export function stepInspectTemplateSanitiser(fact: TaintFact): VerificationStep | null {
  return stepInspectTaintSanitiser(fact);
}
