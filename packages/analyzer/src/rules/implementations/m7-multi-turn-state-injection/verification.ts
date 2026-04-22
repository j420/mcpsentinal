import type { VerificationStep } from "../../../evidence.js";
import type { InjectionSite } from "./gather.js";

export function stepInspectMutation(site: InjectionSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      site.kind === "mutation-call"
        ? `Open this line. Confirm "${site.target_expr}.${site.method}(...)" ` +
          `is invoked on a conversation / history / memory store that is ` +
          `visible to subsequent AI turns.`
        : `Open this line. Confirm "${site.target_expr} = ..." overwrites ` +
          `the conversation / history / memory store rather than a local ` +
          `shadow copy.`,
    target: site.location,
    expected_observation:
      `Write path into conversation state: ${site.target_expr}.${site.method} ` +
      `(or assignment).`,
  };
}

export function stepCheckRead(site: InjectionSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Find every read of the modified state across the codebase and confirm ` +
      `subsequent AI turns actually consume the mutated content (if no agent ` +
      `reads it, the finding is moot).`,
    target: site.location,
    expected_observation: `The modified state is read by the AI agent on the next turn.`,
  };
}

export function stepCheckBoundary(site: InjectionSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Confirm the MCP server does not declare a dedicated "memory" capability ` +
      `that formally owns this write. Tools ARE permitted to write to their ` +
      `own memory namespace; they are NOT permitted to write to the agent's ` +
      `conversation history.`,
    target: site.location,
    expected_observation:
      `No dedicated memory capability; the write crosses the agent boundary.`,
  };
}
