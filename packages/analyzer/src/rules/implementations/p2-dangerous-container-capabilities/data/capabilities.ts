/**
 * P2 — canonical dangerous-capability registry.
 *
 * Each entry identifies a Linux capability (without the CAP_ prefix) and
 * the host-level primitive it unlocks. Matching is case-insensitive and
 * handles both CAP_* and bare forms.
 */

export type CapabilityKind =
  | "mount-escape"
  | "kernel-module-load"
  | "cross-container-debug"
  | "network-manipulation"
  | "packet-capture"
  | "filesystem-bypass"
  | "uid-gid-override"
  | "all-capabilities";

export interface CapabilitySpec {
  /** Bare (non-CAP_-prefixed) capability name. Case-insensitive match. */
  name: string;
  kind: CapabilityKind;
  description: string;
  weight: number;
}

export const DANGEROUS_CAPABILITIES: Record<string, CapabilitySpec> = {
  sys_admin: {
    name: "SYS_ADMIN",
    kind: "mount-escape",
    description:
      "CAP_SYS_ADMIN is colloquially called \"the new root\" — it grants mount, " +
      "namespace, sysctl, and hundreds of other privileged operations. Required " +
      "to exploit CVE-2022-0185 (fsconfig heap overflow) for container escape.",
    weight: 1.0,
  },
  sys_module: {
    name: "SYS_MODULE",
    kind: "kernel-module-load",
    description:
      "CAP_SYS_MODULE lets the container load arbitrary kernel modules — " +
      "direct kernel-level code execution on the host.",
    weight: 1.0,
  },
  sys_ptrace: {
    name: "SYS_PTRACE",
    kind: "cross-container-debug",
    description:
      "CAP_SYS_PTRACE lets the container attach a debugger to any process on " +
      "the host (including sibling containers in shared PID namespaces).",
    weight: 0.85,
  },
  sys_rawio: {
    name: "SYS_RAWIO",
    kind: "kernel-module-load",
    description:
      "CAP_SYS_RAWIO grants raw block-device I/O — direct read/write of host disks.",
    weight: 0.9,
  },
  net_admin: {
    name: "NET_ADMIN",
    kind: "network-manipulation",
    description:
      "CAP_NET_ADMIN lets the container reconfigure the host routing table, " +
      "manipulate iptables, and ARP-spoof other workloads on the bridge.",
    weight: 0.75,
  },
  net_raw: {
    name: "NET_RAW",
    kind: "packet-capture",
    description:
      "CAP_NET_RAW allows raw packet sniffing on interfaces the container can " +
      "see — enables credential harvesting across the pod network.",
    weight: 0.55,
  },
  dac_override: {
    name: "DAC_OVERRIDE",
    kind: "filesystem-bypass",
    description:
      "CAP_DAC_OVERRIDE bypasses file read/write/execute permission checks.",
    weight: 0.75,
  },
  dac_read_search: {
    name: "DAC_READ_SEARCH",
    kind: "filesystem-bypass",
    description:
      "CAP_DAC_READ_SEARCH bypasses directory traversal and read permission checks.",
    weight: 0.7,
  },
  setuid: {
    name: "SETUID",
    kind: "uid-gid-override",
    description:
      "CAP_SETUID allows arbitrary UID transitions — bypasses the container's " +
      "intended user identity.",
    weight: 0.5,
  },
  setgid: {
    name: "SETGID",
    kind: "uid-gid-override",
    description:
      "CAP_SETGID allows arbitrary GID transitions — bypasses the container's " +
      "intended group identity.",
    weight: 0.5,
  },
  all: {
    name: "ALL",
    kind: "all-capabilities",
    description:
      "cap_add: ALL grants every Linux capability to the container — equivalent " +
      "to running with privileged: true.",
    weight: 1.0,
  },
};

/** Host namespace-sharing keys. Charter lethal edge case #4. */
export type NamespaceKind =
  | "privileged"
  | "hostPID"
  | "hostIPC"
  | "hostNetwork"
  | "hostUsers-false";

export interface NamespaceSpec {
  id: NamespaceKind;
  key: string;
  /** Value that triggers (lowercased compare). */
  triggerValues: Record<string, true>;
  description: string;
  weight: number;
}

export const NAMESPACE_TRIGGERS: Record<NamespaceKind, NamespaceSpec> = {
  privileged: {
    id: "privileged",
    key: "privileged",
    triggerValues: { true: true, yes: true, "1": true },
    description:
      "privileged: true disables every Linux security boundary: " +
      "AppArmor, seccomp, cgroups, device access controls, user-namespace mapping.",
    weight: 1.0,
  },
  hostPID: {
    id: "hostPID",
    key: "hostPID",
    triggerValues: { true: true },
    description:
      "hostPID: true shares the host PID namespace — container processes can " +
      "ptrace and signal any process on the node.",
    weight: 0.9,
  },
  hostIPC: {
    id: "hostIPC",
    key: "hostIPC",
    triggerValues: { true: true },
    description:
      "hostIPC: true shares host shared-memory segments and semaphores — " +
      "enables cross-container IPC channel attacks.",
    weight: 0.75,
  },
  hostNetwork: {
    id: "hostNetwork",
    key: "hostNetwork",
    triggerValues: { true: true },
    description:
      "hostNetwork: true shares the host network namespace — same posture " +
      "gap as P10. Kept in P2 because it co-occurs with other host-namespace " +
      "shares in the dangerous-capability cluster.",
    weight: 0.85,
  },
  "hostUsers-false": {
    id: "hostUsers-false",
    key: "hostUsers",
    triggerValues: { false: true },
    description:
      "hostUsers: false disables user-namespace remapping — root-in-container " +
      "is root-on-host.",
    weight: 0.75,
  },
};

/** Tokens that bracket a capability-declaration region on an adjacent line. */
export const CAPABILITY_CONTEXT_TOKENS: Record<string, { description: string }> = {
  capabilities: { description: "k8s capabilities.add / capabilities.drop block" },
  cap_add: { description: "docker-compose cap_add list" },
  "--cap-add": { description: "docker CLI --cap-add flag" },
  add: { description: "securityContext.capabilities.add" },
};
