import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { NoAuthObservation } from "./gather.js";

export function stepAttemptUnauthenticated(obs: NoAuthObservation): VerificationStep {
  return {
    step_type: "test-input",
    instruction:
      `Connect to the MCP server transport (${obs.transport}) without providing any credentials ` +
      `(no Authorization header, no API key query parameter, no mTLS certificate). Issue the ` +
      `\`initialize\` request followed by \`tools/list\`. If both succeed, authentication is ` +
      `genuinely absent.`,
    target: obs.capabilityLocation,
    expected_observation:
      `Server responds 200/OK to \`initialize\` and returns the tool list without a 401/403 or ` +
      `any WWW-Authenticate challenge.`,
  };
}

export function stepCheckReverseProxy(obs: NoAuthObservation): VerificationStep {
  const proxyConfig: Location = {
    kind: "config",
    file: "nginx.conf",
    json_pointer: "/server/location",
  };
  return {
    step_type: "check-config",
    instruction:
      `If the MCP server is fronted by a reverse proxy (nginx / envoy / Traefik / IAP), inspect ` +
      `the proxy configuration and confirm whether auth is terminated at that layer. If yes, ` +
      `document the proxy's auth strategy in an audit note; the finding can then be dismissed ` +
      `with provenance. If no, the server is the auth boundary and E1 stands.`,
    target: proxyConfig,
    expected_observation:
      `Either the proxy enforces auth (dismiss with audit trail) or no proxy exists (E1 stands).`,
  };
}

export function stepCheckBindAddress(obs: NoAuthObservation): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Verify the server's bind address. A 127.0.0.1 bind is not a substitute for authentication ` +
      `— DNS rebinding (Jackson/Bortz/Boneh 2007) makes localhost reachable from any web page the ` +
      `user visits. Unauthenticated localhost MCP servers have been demonstrated-exploited in the ` +
      `wild.`,
    target: obs.capabilityLocation,
    expected_observation:
      `Bind address is 0.0.0.0 / a routable IP (direct network exposure) OR 127.0.0.1 (still ` +
      `exposed via DNS rebinding from a malicious web page).`,
  };
}
