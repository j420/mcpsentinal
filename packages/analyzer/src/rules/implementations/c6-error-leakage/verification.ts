/**
 * C6 verification-step builders — every step's `target` is a structured
 * Location. No regex literals, no long string-literal arrays.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { ErrorLeakFact, ErrorLeakKind } from "./gather.js";

function describeKind(kind: ErrorLeakKind): string {
  switch (kind) {
    case "error-identifier":
      return "a bare error binding (err / error / e / ex / exception)";
    case "stack-property":
      return "a stack-property access (err.stack / err.stackTrace)";
    case "json-stringify-error":
      return "a JSON.stringify(err) call (which walks .message and .stack)";
    case "spread-error":
      return "an `...err` spread (which copies every enumerable error property)";
    case "python-traceback":
      return "a traceback.format_exc() call (full Python stack as a string)";
  }
}

export function stepInspectErrorSource(fact: ErrorLeakFact): VerificationStep {
  const verb = describeKind(fact.kind);
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this position and confirm the expression really is ` +
      `${verb}. If the binding is a sanitised wrapper (sanitizeError(...), ` +
      `formatErrorForClient(...)) the chain does not hold and the finding ` +
      `should be dismissed.`,
    target: fact.sourceLocation,
    expected_observation:
      `${verb}: \`${fact.sourceObserved}\` reaches the response sink without ` +
      `being replaced by an opaque message.`,
  };
}

export function stepInspectResponseSink(fact: ErrorLeakFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this position and confirm the call is a response ` +
      `body method (json / send / write / end / status). The presence of a ` +
      `framework-level error sanitiser higher up the middleware stack would ` +
      `prevent the leak; if no such sanitiser is configured, the finding ` +
      `stands.`,
    target: fact.sinkLocation,
    expected_observation:
      `A \`.${fact.sinkMethod}(...)\` call: \`${fact.sinkObserved}\`. The ` +
      `argument carries internal error state across the trust boundary.`,
  };
}

export function stepCheckProductionGate(fact: ErrorLeakFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      fact.productionGated
        ? `An NODE_ENV / DEBUG gate guards this leak. Confirm the gate ` +
          `actually evaluates to false in production deployments — Docker ` +
          `images and serverless wrappers frequently forget to set NODE_ENV, ` +
          `which collapses the gate to "always true".`
        : `Confirm there is NO surrounding production gate (` +
          `\`if (process.env.NODE_ENV !== "production")\` / DEBUG / verbose ` +
          `mode flag). A pure development-only branch downgrades the finding; ` +
          `its absence escalates it.`,
    target: fact.sinkLocation,
    expected_observation:
      fact.productionGated
        ? "An if-statement wrapping the response that checks NODE_ENV / DEBUG and may evaluate to true in production."
        : "No NODE_ENV or DEBUG gate around the response — the leak runs on every request.",
  };
}
