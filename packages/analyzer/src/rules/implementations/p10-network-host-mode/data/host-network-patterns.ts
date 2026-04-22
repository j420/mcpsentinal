/**
 * P10 — canonical host-network pattern registry.
 */

export type HostNetworkVariant =
  | "docker-compose-network_mode"
  | "kubernetes-hostNetwork"
  | "docker-cli-network-host"
  | "docker-cli-net-host"
  | "k8s-networkMode";

export interface HostNetworkPattern {
  id: HostNetworkVariant;
  /** Canonical key (key/value) or flag token. */
  key: string;
  /** Match kind. */
  matchKind: "kv-value" | "kv-true" | "cli-flag-eq-host";
  /** For kv-value: the value that triggers. Case-insensitive. */
  trigger?: string;
  description: string;
  weight: number;
}

export const HOST_NETWORK_PATTERNS: Record<HostNetworkVariant, HostNetworkPattern> = {
  "docker-compose-network_mode": {
    id: "docker-compose-network_mode",
    key: "network_mode",
    matchKind: "kv-value",
    trigger: "host",
    description: "docker-compose network_mode: host — service shares the host's network namespace.",
    weight: 0.9,
  },
  "k8s-networkMode": {
    id: "k8s-networkMode",
    key: "networkMode",
    matchKind: "kv-value",
    trigger: "host",
    description: "Non-k8s-schema networkMode: host — usually appears in podman / runtime-specific configs.",
    weight: 0.85,
  },
  "kubernetes-hostNetwork": {
    id: "kubernetes-hostNetwork",
    key: "hostNetwork",
    matchKind: "kv-true",
    description: "Kubernetes hostNetwork: true — pod shares the node's network namespace.",
    weight: 0.95,
  },
  "docker-cli-network-host": {
    id: "docker-cli-network-host",
    key: "--network",
    matchKind: "cli-flag-eq-host",
    description: "Docker CLI --network=host — container shares the host network.",
    weight: 0.9,
  },
  "docker-cli-net-host": {
    id: "docker-cli-net-host",
    key: "--net",
    matchKind: "cli-flag-eq-host",
    description: "Docker CLI --net=host (alias for --network=host).",
    weight: 0.9,
  },
};

/** Network-isolation-alternative fingerprints — presence indicates compensation. */
export const ISOLATION_ALTERNATIVE_TOKENS: Record<string, { description: string }> = {
  NetworkPolicy: { description: "Kubernetes NetworkPolicy resource present — inbound/outbound flow control exists." },
  networkpolicy: { description: "Compose-style network policy block." },
  bridge: { description: "Docker bridge network — default isolated network namespace." },
  overlay: { description: "Docker overlay network — encrypted inter-host traffic." },
  internal: { description: "Compose 'internal: true' — network has no outbound egress." },
  "--network=bridge": { description: "Explicit Docker CLI bridge network." },
};
