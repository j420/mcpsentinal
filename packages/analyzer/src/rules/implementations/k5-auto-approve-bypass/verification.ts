/**
 * K5 verification steps — every target a structured Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { K5Fact } from "./gather.js";

export function stepsForFact(fact: K5Fact): VerificationStep[] {
  return [
    inspectBypassSite(fact),
    traceBypassReach(fact),
    checkManifestPolicy(fact),
  ];
}

function inspectBypassSite(fact: K5Fact): VerificationStep {
  switch (fact.kind) {
    case "bypass-flag-assignment":
      return {
        step_type: "inspect-source",
        instruction:
          `Open this file at the indicated line. Confirm the assignment ` +
          `\`${fact.tokenHit} = true\` (or the equivalent object-property / ` +
          `default) controls the confirmation-prompt branch.`,
        target: fact.location,
        expected_observation:
          `An assignment of the literal \`true\` to an identifier / ` +
          `property whose name matches the auto-approve vocabulary.`,
      };
    case "env-var-bypass":
      return {
        step_type: "inspect-source",
        instruction:
          `Open this file at the indicated line. Confirm the ` +
          `${fact.tokenHit} read is consulted when deciding whether to ` +
          `prompt the user.`,
        target: fact.location,
        expected_observation:
          `A \`process.env.<NAME>\` read whose surrounding conditional ` +
          `gates a confirmation prompt.`,
      };
    case "neutered-stub":
      return {
        step_type: "inspect-source",
        instruction:
          `Open this function definition. Confirm it is the function the ` +
          `rest of the code calls to require confirmation. The body is a ` +
          `single unconditional \`return true\` / \`Promise.resolve(true)\`.`,
        target: fact.location,
        expected_observation:
          `A function whose name is one of confirm / askUser / ` +
          `requireApproval / promptUser and whose body is a plain ` +
          `\`return true\`.`,
      };
  }
}

function traceBypassReach(fact: K5Fact): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Trace the use of "${fact.tokenHit}" from this site to at least one ` +
      `destructive tool operation. If an approval path coexists ` +
      `(${fact.hasApprovalPath ? "yes" : "no"} in this file), confirm which ` +
      `branch production traffic takes.`,
    target: fact.location,
    expected_observation:
      fact.hasApprovalPath
        ? `A confirmation-calling path coexists with the bypass — reviewer ` +
          `must decide which path runs under production load.`
        : `No honest-approval path in this module — the bypass is the only ` +
          `code path.`,
  };
}

function checkManifestPolicy(fact: K5Fact): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Open package.json / mcp.json. Confirm whether a documented ` +
      `non-interactive mode policy is declared.`,
    target: {
      kind: "config",
      file: "package.json",
      json_pointer: "/mcp/human_oversight/non_interactive",
    },
    expected_observation:
      fact.hasApprovalPath
        ? `An honest-approval path exists; manifest policy must declare ` +
          `the default.`
        : `No documented human-oversight policy.`,
  };
}
