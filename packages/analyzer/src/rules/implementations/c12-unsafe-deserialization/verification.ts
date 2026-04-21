/**
 * C12 verification-step builders — wrap the shared kit's reusable steps
 * with deserialisation-specific sink verb language.
 */

import type { VerificationStep } from "../../../evidence.js";
import {
  type TaintFact,
  stepInspectTaintSource,
  stepInspectTaintSink,
  stepTraceTaintPath,
  stepInspectTaintSanitiser,
} from "../_shared/taint-rule-kit/index.js";

export function stepInspectDeserSource(fact: TaintFact): VerificationStep {
  return stepInspectTaintSource(fact);
}

export function stepInspectDeserSink(fact: TaintFact): VerificationStep {
  return stepInspectTaintSink(
    fact,
    "an unsafe deserialiser (pickle.loads, yaml.load without SafeLoader, node-serialize.unserialize, marshal.loads, ObjectInputStream.readObject, or PHP unserialize)",
  );
}

export function stepTraceDeserPath(fact: TaintFact): VerificationStep {
  return stepTraceTaintPath(fact);
}

export function stepInspectDeserSanitiser(fact: TaintFact): VerificationStep | null {
  return stepInspectTaintSanitiser(fact);
}
