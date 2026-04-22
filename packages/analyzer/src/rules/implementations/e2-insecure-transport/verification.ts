import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { InsecureTransportObservation } from "./gather.js";

export function stepInspectTransport(obs: InsecureTransportObservation): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Confirm the server transport is ${obs.transport}:// (not ${obs.spec.encrypted_equivalent}://). ` +
      `Open the MCP client's connection configuration or the server's bind configuration and inspect ` +
      `the scheme. Test tools like openssl s_client / curl --tlsv1.2 can demonstrate lack of TLS ` +
      `termination at the transport.`,
    target: obs.capabilityLocation,
    expected_observation:
      `Server accepts ${obs.transport}:// connections and does NOT redirect to ` +
      `${obs.spec.encrypted_equivalent}://.`,
  };
}

export function stepInspectTlsConfig(obs: InsecureTransportObservation): VerificationStep {
  const tlsConfig: Location = {
    kind: "config",
    file: "server.config",
    json_pointer: "/tls",
  };
  return {
    step_type: "check-config",
    instruction:
      `Confirm the server has NO TLS configuration (no certs, no key material, no " +
      "tls.createServer/https.createServer call). If TLS is configured but the scanner observed ` +
      `${obs.transport}, there may be a listen-on-both deployment — the plaintext endpoint still ` +
      `qualifies as a finding.`,
    target: tlsConfig,
    expected_observation:
      `No TLS termination is configured at the server, or a separate plaintext endpoint exists ` +
      `alongside an encrypted one.`,
  };
}

export function stepCaptureNetworkSample(obs: InsecureTransportObservation): VerificationStep {
  return {
    step_type: "test-input",
    instruction:
      `Capture a single MCP round-trip with tcpdump / wireshark on the path between client and ` +
      `server. Confirm the payload is plaintext (human-readable JSON-RPC messages). Any token, ` +
      `parameter, or response value will be visible to any observer in the path.`,
    target: obs.capabilityLocation,
    expected_observation:
      `Packet capture shows JSON-RPC content in cleartext — CWE-319 confirmed.`,
  };
}
