/**
 * C16 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import {
  type TaintFact,
  stepInspectTaintSource,
  stepInspectTaintSink,
  stepTraceTaintPath,
  stepInspectTaintSanitiser,
} from "../_shared/taint-rule-kit/index.js";

export function stepInspectEvalSource(fact: TaintFact): VerificationStep {
  return stepInspectTaintSource(fact);
}

export function stepInspectEvalSink(fact: TaintFact): VerificationStep {
  return stepInspectTaintSink(
    fact,
    "an eval-family call (eval, new Function, setTimeout/setInterval with a string argument, vm.runInNewContext / runInThisContext / runInContext, importlib.import_module, or __import__)",
  );
}

export function stepTraceEvalPath(fact: TaintFact): VerificationStep {
  return stepTraceTaintPath(fact);
}

export function stepInspectEvalSanitiser(fact: TaintFact): VerificationStep | null {
  return stepInspectTaintSanitiser(fact);
}
