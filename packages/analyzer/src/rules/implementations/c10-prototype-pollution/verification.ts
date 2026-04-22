/**
 * C10 — Prototype Pollution: verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { PollutionHit } from "./gather.js";

export function stepInspectPollutionSource(hit: PollutionHit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this position and confirm the expression really is ` +
      `user-controlled. For merge-call hits, the tainted argument is an ` +
      `HTTP body / params / query read or a JSON.parse of an external ` +
      `string. For critical-key-write hits, the key name is a literal ` +
      `"__proto__" / "constructor" / "prototype" — code-level vulnerability, ` +
      `no source needed. For dynamic-key hits, the key binding was traced ` +
      `back to a user-input receiver chain by the AST analyser.`,
    target: hit.sourceLocation,
    expected_observation:
      `A source position whose expression is: ${hit.sourceExpression}. ` +
      `The taint engine categorised it as ${hit.sourceCategory}.`,
  };
}

export function stepInspectPollutionSink(hit: PollutionHit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      hit.kind === "merge-call"
        ? `Open the call site and confirm the receiver really resolves to ` +
          `the merge API the taint engine identified (lodash._.merge / ` +
          `Object.assign / Object.fromEntries / deepmerge / $.extend). A ` +
          `local shadow function with the same name would be a scanner ` +
          `misfire and the finding should be dismissed.`
        : hit.kind === "critical-key"
          ? `Open the assignment and confirm the LHS key is literally one ` +
            `of "__proto__" / "constructor" / "prototype". This is a code- ` +
            `level vulnerability: even without tainted input, the write ` +
            `mutates Object.prototype (or the constructor chain) for the ` +
            `entire process.`
          : `Open the assignment and confirm the key expression binding ` +
            `traces back to an HTTP body/query/params receiver. A guard ` +
            `(hasOwnProperty / key allowlist) must appear between the ` +
            `taint source and this assignment; the analyser reports ` +
            `guardPresent=${hit.guardPresent}.`,
    target: hit.sinkLocation,
    expected_observation:
      `A sink expression: ${hit.sinkExpression}. The pollution vector kind is ${hit.kind}.`,
  };
}

export function stepInspectGuard(hit: PollutionHit, fileLocation: Location): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction: hit.guardPresent
      ? `A guard was observed in the enclosing scope. Confirm the guard ` +
        `actually runs BEFORE the sink on every control-flow path. A guard ` +
        `inside an if-branch whose else-branch skips the check is not an ` +
        `adequate mitigation — the rule will still fire with a charter_` +
        `confidence_cap factor because static analysis cannot prove ` +
        `coverage.`
      : `No guard (hasOwnProperty / Object.create(null) construction / ` +
        `allowlist function) was detected in the enclosing scope. The ` +
        `merge / write can pollute any property name the attacker sends.`,
    target: fileLocation,
    expected_observation: hit.guardPresent
      ? `A pre-sink guard call at module scope or inside the enclosing ` +
        `function. Detail: ${hit.guardDetail}.`
      : `No hasOwnProperty.call / Object.create(null) / freeze / seal / ` +
        `allowlist present at module scope or inside the enclosing function.`,
  };
}

export function stepConfirmScope(hit: PollutionHit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Confirm the polluted object is shared across the request lifecycle. ` +
      `A single-request object that gets discarded carries a much lower ` +
      `impact than a module-scoped config merged into on every request. ` +
      `Look at the variable's declaration: module-level const? session ` +
      `store? global process object? The wider the scope, the worse the ` +
      `exploit.`,
    target: hit.sinkLocation,
    expected_observation:
      `A declaration of the merge target or the assigned object at module ` +
      `scope, or stored into a persistent container (session store, ` +
      `module-level cache, process.env). Confirming a shared-scope object ` +
      `upgrades the finding from "this request's object" to "every future ` +
      `object in the process".`,
  };
}
