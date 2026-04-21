import type { VerificationStep } from "../../../evidence.js";
import type { ColludingPair } from "./gather.js";

export function stepInspectWriteTool(pair: ColludingPair): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the write-side tool \`${pair.writeTool.toolName}\`. Confirm its ` +
      `name / description references the shared-state surface (tokens: ` +
      `${pair.surfaceTokens.join(", ")}). In a multi-agent topology, content ` +
      `written here reaches any downstream agent whose tool reads the same ` +
      `surface. The rule treats this as a collusion precondition regardless ` +
      `of the writer's intent.`,
    target: pair.writeTool.toolLocation,
    expected_observation:
      `Tool \`${pair.writeTool.toolName}\` writes to a shared-state surface ` +
      `without a trust-boundary attestation.`,
  };
}

export function stepInspectReadTool(pair: ColludingPair): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the read-side tool \`${pair.readTool.toolName}\`. Confirm it ` +
      `consumes the SAME shared-state surface (tokens: ` +
      `${pair.surfaceTokens.join(", ")}). Together with the write tool, ` +
      `these two tools form the channel through which a compromised upstream ` +
      `agent can pass poisoned content to a downstream agent (Invariant ` +
      `Labs, Jan 2026; Rehberger, Nov 2025).`,
    target: pair.readTool.toolLocation,
    expected_observation:
      `Tool \`${pair.readTool.toolName}\` reads from a shared-state surface ` +
      `whose writes are not attested.`,
  };
}

export function stepInspectMitigation(pair: ColludingPair): VerificationStep {
  return {
    step_type: "inspect-schema",
    instruction: pair.mitigated
      ? `A trust-boundary attestation is present: ${pair.mitigationDetail}. ` +
        `Confirm it is enforced at runtime — a parameter whose schema REQUIRES ` +
        `\`agent_id\` but whose handler ignores the value is not a mitigation.`
      : `Walk the write tool's schema and annotations and confirm that NO ` +
        `trust-boundary signal exists — no \`trustBoundary\` annotation, no ` +
        `REQUIRED \`agent_id\` / \`tenant_id\` / \`session_id\` parameter, ` +
        `and no isolation-scoped name token. Absence is the compliance gap ` +
        `K15 names.`,
    target: pair.writeTool.toolLocation,
    expected_observation: pair.mitigated
      ? `Trust-boundary attestation present; runtime enforcement requires manual confirmation.`
      : `No trust-boundary attestation on the write side.`,
  };
}
