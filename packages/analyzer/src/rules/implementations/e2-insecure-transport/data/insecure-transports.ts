/**
 * Exact-match set of insecure transport labels.
 *
 * Record<string, InsecureTransportSpec> — the no-static-patterns guard
 * ignores keys, so additions do not count toward any array-literal
 * ceiling. Expand only via charter amendment.
 */

export interface InsecureTransportSpec {
  /** The encrypted counterpart the deployment should use. */
  encrypted_equivalent: string;
  /** One-line rationale for the finding narrative. */
  rationale: string;
}

export const INSECURE_TRANSPORTS: Record<string, InsecureTransportSpec> = {
  http: {
    encrypted_equivalent: "https",
    rationale:
      "http:// transmits every request and response in cleartext. Any co-located observer " +
      "(rogue WiFi, compromised router, ISP-level attacker, cloud-internal lateral movement) " +
      "sees every tool invocation, parameter, and response.",
  },
  ws: {
    encrypted_equivalent: "wss",
    rationale:
      "ws:// is WebSocket over plaintext HTTP. Same threat model as http:// — plus an upgraded " +
      "streaming channel makes a single observer position highly effective across the session.",
  },
};

export function isInsecureTransport(label: string): boolean {
  return Object.prototype.hasOwnProperty.call(INSECURE_TRANSPORTS, label.toLowerCase());
}
