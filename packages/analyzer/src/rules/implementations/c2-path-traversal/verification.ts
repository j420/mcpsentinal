/**
 * C2 verification-step builders — wrap the shared taint-rule-kit's
 * reusable steps with path-traversal-specific sink verb language.
 */

import type { VerificationStep } from "../../../evidence.js";
import {
  type TaintFact,
  stepInspectTaintSource,
  stepInspectTaintSink,
  stepTraceTaintPath,
  stepInspectTaintSanitiser,
} from "../_shared/taint-rule-kit/index.js";

export function stepInspectPathSource(fact: TaintFact): VerificationStep {
  return stepInspectTaintSource(fact);
}

export function stepInspectPathSink(fact: TaintFact): VerificationStep {
  return stepInspectTaintSink(
    fact,
    "a filesystem read/write (fs.readFile / fs.readFileSync / fs.writeFile / fs.writeFileSync / createReadStream / createWriteStream / open / Python open())",
  );
}

export function stepTracePathFlow(fact: TaintFact): VerificationStep {
  return stepTraceTaintPath(fact);
}

export function stepInspectPathSanitiser(fact: TaintFact): VerificationStep | null {
  return stepInspectTaintSanitiser(fact);
}
