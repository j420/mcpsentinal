/**
 * C8 verification-step builders — every step's `target` is a structured
 * Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { NetworkBindFact } from "./gather.js";

export function stepInspectListenCall(fact: NetworkBindFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this position and confirm the call binds the ` +
      `server to a network-reachable interface (0.0.0.0, ::, or default-` +
      `host). If the deployment is workstation-local, change the host to ` +
      `127.0.0.1 / localhost. If the deployment is intentionally network-` +
      `reachable, the surrounding code MUST register an authentication ` +
      `middleware before this listen call.`,
    target: fact.location,
    expected_observation:
      `A bind / listen / uvicorn.run call with a wildcard host or default ` +
      `host (which defaults to wildcard on most stacks). Observed: ` +
      `\`${fact.observed}\`.`,
  };
}

export function stepCheckAuthMiddleware(fact: NetworkBindFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      fact.authMiddlewarePresent
        ? `An auth middleware was detected in this file but the network bind ` +
          `still fired the rule. Confirm the middleware actually protects the ` +
          `tool-invocation routes (not just /health or /metrics).`
        : `Walk the file and any sibling middleware modules for a ` +
          `\`<app>.use(<auth>)\` call (authMiddleware, requireAuth, ` +
          `passport.authenticate(...), verifyJwt, verifyApiKey, etc.). The ` +
          `rule did NOT find one — confirm by reading the imports and the ` +
          `middleware registration block.`,
    target: fact.location,
    expected_observation:
      fact.authMiddlewarePresent
        ? "An auth middleware is wired but does not cover the bind."
        : "No auth middleware is wired anywhere in the source. Tool invocations on this listener are unauthenticated.",
  };
}

export function stepCheckDeploymentScope(fact: NetworkBindFact): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Inspect the deployment configuration (Dockerfile EXPOSE, ` +
      `docker-compose port mappings, Kubernetes Service type) to confirm ` +
      `the network surface is intended. A loopback-only deployment turns ` +
      `the bind into a non-issue; a publicly-routable deployment makes the ` +
      `missing auth a critical operational risk.`,
    target: fact.location,
    expected_observation:
      "Deployment manifest confirms the listener is intentionally exposed beyond loopback.",
  };
}
