/**
 * L4 verification-step builders. Every step carries a structured Location
 * target. Steps chain the auditor from the config literal through the
 * specific primitive to the write/load site.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { L4ConfigContext, L4Primitive } from "./gather.js";

/** Step 1 — inspect the config literal. */
export function stepInspectConfigLiteral(ctx: L4ConfigContext): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file and confirm this object-literal IS the MCP config payload ` +
      `(has an \`mcpServers\` key, or sits under a known MCP config filename write). ` +
      `If it is example code in a comment or a test-fixture docstring, the finding ` +
      `should be dismissed. If it is a live config built at runtime, the ` +
      `classification below applies.`,
    target: ctx.literalLocation,
    expected_observation:
      `An object literal matching the MCP config shape (mcpServers → { name: ` +
      `{ command, args, env } }).`,
  };
}

/** Step 2 — inspect the specific primitive site (command / args / env child). */
export function stepInspectPrimitive(primitive: L4Primitive): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Inspect the ${primitiveLabel(primitive)} at this position. ${primitive.detail}`,
    target: primitive.location,
    expected_observation: primitive.observed,
  };
}

/** Step 3 — inspect the target config file (if the literal is being written). */
export function stepInspectTargetConfigFile(ctx: L4ConfigContext): VerificationStep {
  if (ctx.targetConfigFile === null) {
    return {
      step_type: "check-config",
      instruction:
        `No writeFileSync / writeFile targeting an MCP config filename was observed ` +
        `in the same file. Trace the object literal's callers — if it is EXPORTED ` +
        `and consumed by an out-of-file loader, the supply-chain primitive still ` +
        `applies; if it is local test data, the finding is dismissible.`,
      target: ctx.literalLocation,
      expected_observation:
        `Either an out-of-file consumer that reads this literal into an MCP config ` +
        `file, or no external consumer (dismiss).`,
    };
  }
  return {
    step_type: "check-config",
    instruction:
      `The literal flows into a writeFileSync call whose path matches a known MCP ` +
      `config filename. Open the target file and confirm the MCP client will ` +
      `auto-load it on next launch. For Cursor and Claude Code this is CVE-2025-59536 ` +
      `territory — the command executes BEFORE the user sees the trust dialog.`,
    target: ctx.targetConfigFile,
    expected_observation:
      `An MCP-config file the local IDE/agent auto-loads; the primitive identified ` +
      `above executes on next launch.`,
  };
}

function primitiveLabel(p: L4Primitive): string {
  switch (p.kind) {
    case "shell-interpreter-command":
      return "command field (shell interpreter)";
    case "fetch-and-execute-in-args":
      return "args entry (fetch-and-execute payload)";
    case "api-base-env-redirect":
      return "env block (API base redirect)";
    case "sensitive-env-in-args":
      return "args / env entry (sensitive credential reference)";
  }
}

export function stepTargetLocationFor(ctx: L4ConfigContext): Location {
  return ctx.targetConfigFile ?? ctx.literalLocation;
}
