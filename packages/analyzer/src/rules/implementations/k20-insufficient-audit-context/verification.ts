/**
 * K20 verification-step builders — each step carries a structured
 * Location target (v2 standard §4). An auditor reads these steps top
 * to bottom to reproduce the observation.
 *
 * No regex, no long string-literal arrays.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { BindingsSite, LoggerCallSite, MixinFormatSite } from "./gather.js";

/**
 * Step 1 — visit the log call site.
 */
export function stepInspectCall(site: LoggerCallSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this line and confirm that the ${site.receiverLabel}.${site.method}(...) ` +
      `invocation is on a normal control-flow path (not inside a development-only ` +
      `branch). Read the argument list: the audit record for this call is exactly what ` +
      `the runtime logger will emit — an incident responder opening the log must be ` +
      `able to correlate this record to a request, attribute it to a caller, and ` +
      `determine whether the operation succeeded.`,
    target: site.location,
    expected_observation:
      site.isStringOnly
        ? `A ${site.receiverLabel}.${site.method}(...) call whose only argument is a string — ` +
          `no object-literal carrying correlation id, caller identity, tool name, ` +
          `timestamp schema, or outcome.`
        : `A ${site.receiverLabel}.${site.method}(...) call whose object-literal arguments ` +
          `observably carry fewer than 2 recognised audit-field aliases.`,
  };
}

/**
 * Step 2 — inspect any bindings sites contributed by .child(<obj>) on
 * the receiver chain. Emitted once per bindings site so the auditor
 * can corroborate which fields the bindings already propagate.
 */
export function stepInspectBindings(binding: BindingsSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `The call receiver chain includes a .child(...) (or equivalent bindings) call ` +
      `at this location. Audit-field aliases propagated via bindings are considered ` +
      `present at every downstream log call. Open this line and confirm the bindings ` +
      `object contains the fields the rule recorded.`,
    target: binding.location,
    expected_observation:
      binding.observedAliases.length > 0
        ? `Bindings object carrying recognised aliases: ${binding.observedAliases.join(", ")}.`
        : `Bindings call observed but object carries no recognised audit-field aliases.`,
  };
}

/**
 * Step 3 — inspect a pino mixin / winston format constructor if one
 * was observed in scope. This is an invisibility warning, not a fail:
 * the constructor may add fields at emission time that the static
 * analyser cannot enumerate.
 */
export function stepInspectMixinFormat(mix: MixinFormatSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `A mixin / format transformer is observed in scope. Open this line and ` +
      `confirm whether the transformer adds the correlation id / caller identity / ` +
      `tool name / timestamp / outcome fields at emission time. If it does, the ` +
      `call site's apparent emptiness is not a real gap — the transformer closes it.`,
    target: mix.location,
    expected_observation:
      `A mixin(...) / format.combine(...) / format.timestamp(...) configuration that ` +
      `injects fields into every emitted record.`,
  };
}

/**
 * Step 4 — check whether the file imports a structured logger. When
 * no logger is imported AND the call receiver is console, K1 is the
 * primary rule for the architectural gap; K20 is the backstop for the
 * per-call audit-context gap.
 */
export function stepCheckLoggerImport(
  fileLocation: Location & { kind: "source" },
  importPresent: boolean,
): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction: importPresent
      ? `A structured logger IS imported in this file. Confirm that the flagged call ` +
        `cannot be trivially refactored to use the imported logger with the missing ` +
        `fields attached — a trivial refactor is a one-line fix that closes the audit ` +
        `gap.`
      : `No structured logger is imported in this file. K1 names the architectural ` +
        `gap; K20 additionally names the per-call audit-context gap at the flagged ` +
        `line. Confirm that the call does not rely on an out-of-file middleware layer ` +
        `(AsyncLocalStorage, morgan, etc.) to inject the missing fields at emission.`,
    target: fileLocation,
    expected_observation: importPresent
      ? `An import of a structured logger at module scope that the flagged call does ` +
        `not fully exploit.`
      : `No structured logger imported at module scope.`,
  };
}

/**
 * Step 5 — document the remediation. The auditor sees which groups
 * are missing, allowing a one-line fix by adding the missing fields.
 */
export function stepRemediationPreview(
  site: LoggerCallSite,
  missingGroups: string[],
): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Replace the flagged call with a structured form that adds the missing audit ` +
      `groups: ${missingGroups.length > 0 ? missingGroups.join(", ") : "none"}. ` +
      `Example: \`logger.info({ correlation_id, user_id, tool, outcome, timestamp }, ` +
      `"handled tool call")\`. The correlation id should be propagated from the ` +
      `request context (AsyncLocalStorage, pino.child bindings).`,
    target: site.location,
    expected_observation:
      `After the fix, a single structured log record that an incident responder can ` +
      `correlate, attribute, and reconstruct.`,
  };
}
