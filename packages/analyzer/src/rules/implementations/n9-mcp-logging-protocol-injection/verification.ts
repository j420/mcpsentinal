import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { LogInjectSite } from "./gather.js";

export function buildLogFlowStep(site: LogInjectSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open line ${site.line} and confirm ${site.user_input.label} reaches ` +
      `${site.log_surface.label} on the same line.`,
    target: site.location as Location,
    expected_observation: `Line reads: "${site.line_text}".`,
  };
}

export function buildNotificationTraceStep(site: LogInjectSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      site.log_surface.variant === "mcp_notification"
        ? `Trace how the MCP client processes notifications/message.data. ` +
          `Most clients forward this into audit storage and — in agentic ` +
          `clients — into the model's context window. Attacker bytes land ` +
          `in both paths.`
        : `Trace how the logger plumbs into the MCP notifications/message ` +
          `emitter. Many MCP SDKs bridge logger calls into notifications, ` +
          `so user input in a log call propagates through the wire ` +
          `protocol.`,
    target: site.location as Location,
    expected_observation:
      `Adversary-controlled bytes appear in the client-side audit log ` +
      `and agent-context paths.`,
  };
}

export function buildSanitiserStep(site: LogInjectSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Verify whether a sanitiser (escape / sanitise / strip / redact) is ` +
      `applied to the user input before emission.`,
    target: site.location as Location,
    expected_observation:
      site.sanitised_nearby
        ? `Sanitiser fragment on the same line — confirm it covers the user ` +
          `bytes before they reach the log surface.`
        : `No sanitiser on the line. User bytes pass through verbatim.`,
  };
}
