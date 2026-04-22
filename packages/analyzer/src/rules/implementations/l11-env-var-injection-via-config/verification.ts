/**
 * L11 verification-step builders. Each step carries a structured Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { L11Fact } from "./gather.js";

/** Step 1 — inspect the containing MCP config literal. */
export function stepInspectLiteral(fact: L11Fact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file and confirm this object-literal is an MCP configuration ` +
      `and not test data or documentation. The env block below is passed to ` +
      `the MCP client which in turn forwards it to the spawned server process.`,
    target: fact.literalLocation,
    expected_observation:
      `An object literal with an mcpServers key whose server entries include ` +
      `an env block.`,
  };
}

/** Step 2 — inspect the specific env-key entry. */
export function stepInspectEnvEntry(fact: L11Fact): VerificationStep {
  const caseNote = fact.caseMutated
    ? ` Note: the observed spelling "${fact.observedKey}" differs from the ` +
      `canonical "${fact.canonicalKey}". On Windows the server process still ` +
      `interprets it as the risky variable; on Linux the two may be different ` +
      `identifiers so confirm the deployment target.`
    : "";
  return {
    step_type: "inspect-source",
    instruction:
      `Inspect the env.${fact.observedKey} entry. ${fact.rationale}.${caseNote}`,
    target: fact.entryLocation,
    expected_observation:
      `env.${fact.observedKey} = ${fact.observedValue.slice(0, 120)} — a ` +
      `${fact.riskClass} primitive.`,
  };
}

/** Step 3 — check whether an allowlist filter could have caught this. */
export function stepCheckAllowlistFilter(fact: L11Fact): VerificationStep {
  return {
    step_type: "check-config",
    instruction: fact.coexistsWithSafeKeys
      ? `The same env block contains safe keys (PORT, HOST, LOG_LEVEL, NODE_ENV). ` +
        `An allowlist filter would have passed those entries while rejecting ` +
        `${fact.canonicalKey}. Confirm the config parser has no such filter before ` +
        `the env block reaches spawn().`
      : `Confirm that neither the MCP client NOR the config parser validates env ` +
        `keys against a safe-list before spawning. On Claude Code and Cursor (as ` +
        `of CVE-2026-21852) there is no such filter, so every env key in the ` +
        `config reaches the server process unchanged.`,
    target: fact.entryLocation,
    expected_observation:
      `No env-key allowlist between the config literal and the spawned process.`,
  };
}
