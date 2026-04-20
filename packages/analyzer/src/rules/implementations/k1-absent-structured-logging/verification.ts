/**
 * K1 verification-step builders — each step carries a structured Location
 * target (v2 standard §4). The step list is what an auditor reads to
 * reproduce the observation: "open this file, read this line, confirm
 * what the rule claims."
 *
 * No regex, no long string-literal arrays.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { ConsoleCallSite, HandlerSite, DisableLoggingSite } from "./gather.js";
import type { Location } from "../../location.js";

/**
 * Step 1 — visit the handler registration and confirm it handles outside input.
 */
export function stepInspectHandler(handler: HandlerSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file, jump to the handler registration, and confirm it is reachable ` +
      `from the server's external entry point (that is, it actually dispatches on ` +
      `incoming requests / tool calls — not a utility factory).`,
    target: handler.location,
    expected_observation:
      `A handler registration of the form ${handler.label}(...) that dispatches on ` +
      `externally-arriving events.`,
  };
}

/**
 * Step 2 — visit each console call site inside the handler scope.
 */
export function stepInspectConsoleCall(call: ConsoleCallSite, handler: HandlerSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this line and confirm console.${call.method}(...) is executed ` +
      `during normal handler processing (not inside a branch that is only reachable in ` +
      `development, for example behind \`if (process.env.NODE_ENV === "development")\`).`,
    target: call.location,
    expected_observation:
      `A console.${call.method}(...) call inside the lexical scope of ${handler.label} ` +
      `that runs on the normal control-flow path.`,
  };
}

/**
 * Step 3 — check whether the file imports a structured logger (mitigation check).
 * If NO logger import was found in this file, we still emit a verification step so
 * the auditor can corroborate the absence by reading the top of the file.
 */
export function stepCheckLoggerImport(
  fileLocation: Location & { kind: "source" },
  importFound: boolean,
): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction: importFound
      ? `A structured logger IS imported at the top of this file. Confirm that it is ` +
        `not then immediately wrapped around console.* — e.g. by a pino transport ` +
        `misconfiguration — before concluding the gap is real.`
      : `Read the top of this file. Confirm that NO structured logger (pino, winston, ` +
        `bunyan, tslog, log4js, structlog, loguru) is imported in this module.`,
    target: {
      kind: "source",
      file: fileLocation.file,
      line: 1,
      col: 1,
    },
    expected_observation: importFound
      ? `An import of a structured logger at module scope that is not used inside the ` +
        `handler flagged in step 1.`
      : `No import of a structured logger — a file-level gap, not a handler-level one.`,
  };
}

/**
 * Step 4 — check the dependency list for a structured logger.
 */
export function stepCheckDependency(
  hasDep: boolean,
  depLocation: Location | null,
): VerificationStep {
  if (hasDep && depLocation && depLocation.kind === "dependency") {
    return {
      step_type: "check-dependency",
      instruction:
        `A structured logger IS in the project dependency list. Verify that it is wired ` +
        `into at least one production code path — if not, the project has the library ` +
        `installed but not configured, which is a different compliance gap.`,
      target: depLocation,
      expected_observation:
        `${depLocation.ecosystem}:${depLocation.name}@${depLocation.version} is ` +
        `installed but not consumed by the flagged handler.`,
    };
  }
  return {
    step_type: "check-dependency",
    instruction:
      `Open package.json (or pyproject.toml / requirements.txt) and confirm NO ` +
      `structured logging library is listed. This escalates the finding from ` +
      `"handler-level miss" to "project-wide absence".`,
    target: {
      kind: "config",
      file: "package.json",
      json_pointer: "/dependencies",
    },
    expected_observation:
      `No structured logger (pino, winston, bunyan, tslog, log4js, structlog, loguru) ` +
      `in the dependency list.`,
  };
}

/**
 * Audit-erasure variant — when logging.disable() or logger.silent = true is found.
 */
export function stepInspectSuppression(disable: DisableLoggingSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open this line and confirm the suppression is reachable on the normal ` +
      `control-flow path (not guarded by a test-only flag, not inside a conditional ` +
      `that the production build dead-code-eliminates).`,
    target: disable.location,
    expected_observation:
      disable.variant === "logging.disable"
        ? `An unconditional logging.disable(...) call on the startup path.`
        : `An unconditional logger.silent = true (or logger.level = "silent") ` +
          `assignment on the startup path.`,
  };
}
