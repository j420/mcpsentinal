/**
 * J1 verification-step builders. Every step carries a structured Location
 * target. The sequence walks an auditor from the file-scope write
 * primitive through to the victim agent's config file.
 *
 * Step chain: sourceWrite → tracePath → targetHost → checkSanitiser.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { J1Fact } from "./gather.js";

/** Step 1 — open the writeFile call and confirm it's a real fs write. */
export function stepInspectWritePrimitive(fact: J1Fact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file and confirm this is an unguarded filesystem write ` +
      `(fs.writeFileSync / fs.writeFile / fs.appendFileSync / fs-extra.outputFile / ` +
      `fs.promises.writeFile). A write guarded by an env-only dev flag that production ` +
      `dead-code-eliminates does NOT qualify — confirm the control-flow path reaches ` +
      `this call under normal operation.`,
    target: fact.sinkLocation,
    expected_observation:
      `A filesystem write API call whose destination argument derives from the ` +
      `untrusted source above.`,
  };
}

/** Step 2 — walk the taint path and confirm every hop. */
export function stepTracePathToConfigTarget(fact: J1Fact): VerificationStep {
  const target: Location =
    fact.path.length > 0 ? fact.path[0].location : fact.sinkLocation;
  const obs =
    fact.path.length === 0
      ? `Direct source→sink flow (zero hops). The write's path argument is the ` +
        `untrusted expression itself.`
      : `Walk the ${fact.path.length} hop(s) — assignment, destructure, template ` +
        `embed, or function boundary — and confirm each is a real data-flow step, ` +
        `not a coincidental identifier reuse.`;
  return {
    step_type: "trace-flow",
    instruction:
      `Follow the taint path from the source expression to the write argument. Each ` +
      `hop must be a real data-flow step (assignment / destructure / template-embed / ` +
      `parameter bind / return value). A broken hop invalidates the chain.`,
    target,
    expected_observation: obs,
  };
}

/**
 * Step 3 — confirm the destination resolves to a different agent's config
 * file on the configured platform. The step target is the config Location.
 */
export function stepVerifyVictimAgentConfig(fact: J1Fact): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Identify whose config this is. The path suffix \`${fact.targetSuffix}\` ` +
      `belongs to ${fact.targetRole} (${fact.targetHost}). Confirm it is NOT the ` +
      `server's own namespace. Cross-platform: if the path is built with process.env ` +
      `or homedir(), repeat the check on macOS (~/.claude/), Linux (~/.claude/), and ` +
      `Windows (%APPDATA%\\.claude\\) to verify each resolves into the victim agent's ` +
      `config directory. Also check for symlinks — a namespace-internal path that ` +
      `resolves via a symlink into ${fact.targetSuffix} is equally dangerous.`,
    target: fact.targetLocation,
    expected_observation:
      `The resolved path lands on ${fact.targetRole} — a different AI agent's ` +
      `configuration file than the server's own namespace.`,
  };
}

/**
 * Step 4 — verify there is no charter-audited sanitiser on the path.
 * Emitted unconditionally so the auditor sees "I looked for a guard here"
 * on every J1 finding, not just the sanitised ones.
 */
export function stepInspectSanitiser(fact: J1Fact): VerificationStep {
  const target: Location = fact.sanitiser ? fact.sanitiser.location : fact.sinkLocation;
  if (!fact.sanitiser) {
    return {
      step_type: "inspect-source",
      instruction:
        `Confirm that no path-scope assertion, user-confirmation gate, or config- ` +
        `target allowlist runs before the write. The J1 charter's audited set is ` +
        `{assertPathInsideNamespace, confirmCrossAgentWrite, requireUserApproval, ` +
        `validateConfigTarget, enforceSameAgentScope}. A validator not on this list ` +
        `can be CLAIMED to sanitise but a reviewer MUST audit it.`,
      target,
      expected_observation:
        `No sanitiser from the J1 charter list intercepts the path between the source ` +
        `and the write.`,
    };
  }
  return {
    step_type: "inspect-source",
    instruction: fact.sanitiser.charterKnown
      ? `Sanitiser \`${fact.sanitiser.name}\` IS on the J1 charter list. Confirm ` +
        `the binding resolves to the library implementation (not a locally-shadowed ` +
        `identifier) and that it rejects — not silently allows — paths outside this ` +
        `server's namespace.`
      : `Sanitiser \`${fact.sanitiser.name}\` is NOT on the J1 charter list. Open its ` +
        `definition and confirm it actually asserts the destination is inside the ` +
        `server's own namespace. If it merely calls path.normalize() or ` +
        `JSON.stringify() it does NOT prevent a cross-agent config write.`,
    target,
    expected_observation: fact.sanitiser.charterKnown
      ? `\`${fact.sanitiser.name}\` is invoked on the path before the write and ` +
        `rejects agent-config targets.`
      : `\`${fact.sanitiser.name}\` is invoked but its body a reviewer MUST audit.`,
  };
}
