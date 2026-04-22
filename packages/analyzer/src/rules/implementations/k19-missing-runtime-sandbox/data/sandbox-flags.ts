/**
 * K19 — canonical sandbox-disable flag registry.
 *
 * Typed Record, not a regex alternation or a string-literal array > 5.
 * Each entry declares:
 *   - `matchKind`: how the flag surfaces in config
 *     - "cli-flag": Docker CLI (e.g. --privileged)
 *     - "kv-true":  a KEY: true / KEY=true / KEY yes / KEY 1 setting
 *     - "kv-value": a KEY: specific-VALUE setting (seccomp: Unconfined)
 *     - "cap-add":  a capability addition (split on commas / YAML list)
 *   - `key`: the canonical key name the matcher looks for
 *   - `trigger`: (for kv-value) the value that triggers the finding
 *   - `category`: the §5.2 class the auditor reads
 *   - `cveReference`: real CVE that weaponises this flag
 *   - `weight`: severity contribution
 */

export type FlagCategory =
  | "privileged-mode"
  | "capability-addition"
  | "security-profile-disable"
  | "host-namespace-share"
  | "privilege-escalation";

export interface SandboxFlag {
  id: string;
  matchKind: "cli-flag" | "kv-true" | "kv-value" | "cap-add";
  /** Canonical key or flag name. Case-insensitive match by the gatherer. */
  key: string;
  /** For kv-value: the specific value that triggers. Case-insensitive. */
  trigger?: string;
  category: FlagCategory;
  /** CVE that weaponises this specific flag, if any. */
  cveReference?: string;
  /** Human-readable description of the risk. */
  description: string;
  /** Severity weight 0..1. */
  weight: number;
}

export const SANDBOX_FLAGS: Record<string, SandboxFlag> = {
  "docker-cli-privileged": {
    id: "docker-cli-privileged",
    matchKind: "cli-flag",
    key: "--privileged",
    category: "privileged-mode",
    cveReference: "CVE-2022-0492",
    description: "Docker --privileged flag — full host kernel access, CAP_SYS_ADMIN equivalent.",
    weight: 1.0,
  },
  "k8s-privileged": {
    id: "k8s-privileged",
    matchKind: "kv-true",
    key: "privileged",
    category: "privileged-mode",
    cveReference: "CVE-2022-0492",
    description: "Kubernetes securityContext.privileged — container has host-equivalent privileges.",
    weight: 1.0,
  },
  "k8s-allow-privilege-escalation": {
    id: "k8s-allow-privilege-escalation",
    matchKind: "kv-true",
    key: "allowPrivilegeEscalation",
    category: "privilege-escalation",
    description: "allowPrivilegeEscalation: true — child processes can gain more privileges than their parent via setuid binaries.",
    weight: 0.8,
  },
  "k8s-hostPID": {
    id: "k8s-hostPID",
    matchKind: "kv-true",
    key: "hostPID",
    category: "host-namespace-share",
    cveReference: "CVE-2019-5736",
    description: "hostPID: true — container sees every process on the host node via /proc (enables credential / secret theft from sibling containers).",
    weight: 0.9,
  },
  "k8s-hostIPC": {
    id: "k8s-hostIPC",
    matchKind: "kv-true",
    key: "hostIPC",
    category: "host-namespace-share",
    description: "hostIPC: true — container shares SysV IPC segments and POSIX shared memory with the host.",
    weight: 0.75,
  },
  "k8s-hostNetwork": {
    id: "k8s-hostNetwork",
    matchKind: "kv-true",
    key: "hostNetwork",
    category: "host-namespace-share",
    description: "hostNetwork: true — container shares the host network stack (tracked primarily by P10; also a sandbox defeat).",
    weight: 0.8,
  },
  "docker-cli-pid-host": {
    id: "docker-cli-pid-host",
    matchKind: "kv-value",
    key: "--pid",
    trigger: "host",
    category: "host-namespace-share",
    description: "Docker --pid=host — host PID namespace sharing from the CLI.",
    weight: 0.9,
  },
  "docker-cli-ipc-host": {
    id: "docker-cli-ipc-host",
    matchKind: "kv-value",
    key: "--ipc",
    trigger: "host",
    category: "host-namespace-share",
    description: "Docker --ipc=host — host IPC namespace sharing from the CLI.",
    weight: 0.75,
  },
  "seccomp-unconfined": {
    id: "seccomp-unconfined",
    matchKind: "kv-value",
    key: "seccomp",
    trigger: "unconfined",
    category: "security-profile-disable",
    cveReference: "CVE-2022-0492",
    description: "Seccomp profile set to Unconfined — all syscalls reachable including mount/pivot_root (enables cgroup escape).",
    weight: 0.85,
  },
  "apparmor-unconfined": {
    id: "apparmor-unconfined",
    matchKind: "kv-value",
    key: "apparmor",
    trigger: "unconfined",
    category: "security-profile-disable",
    description: "AppArmor profile set to unconfined — MAC-based file-access restrictions disabled.",
    weight: 0.8,
  },
  "read-only-root-fs-false": {
    id: "read-only-root-fs-false",
    matchKind: "kv-true",
    key: "readOnlyRootFilesystem-inverted",
    // Inverted: we actually check readOnlyRootFilesystem: false, NOT true. Encoded
    // in the gatherer's dedicated handler rather than via a generic kv-true match.
    category: "security-profile-disable",
    description: "Container root filesystem is writable — a write primitive in a container with the host's /etc mounted can pivot to persistence.",
    weight: 0.6,
  },
};

/**
 * Dangerous capability names. When matchKind = "cap-add" the gatherer
 * recognises additions of these capabilities regardless of syntax.
 */
export const DANGEROUS_CAPABILITIES: Record<string, { description: string; weight: number }> = {
  ALL: {
    description: "CAP_ALL — every Linux capability added to the container. Equivalent to --privileged.",
    weight: 1.0,
  },
  SYS_ADMIN: {
    description: "CAP_SYS_ADMIN — mount, pivot_root, namespace creation; the 'new root' of Linux capabilities (CVE-2022-0185).",
    weight: 0.95,
  },
  SYS_PTRACE: {
    description: "CAP_SYS_PTRACE — attach to sibling processes; read their memory; intercept secrets.",
    weight: 0.85,
  },
  SYS_MODULE: {
    description: "CAP_SYS_MODULE — load kernel modules; enables arbitrary kernel code execution.",
    weight: 0.95,
  },
  NET_ADMIN: {
    description: "CAP_NET_ADMIN — configure network interfaces; ARP spoof; bind any port.",
    weight: 0.75,
  },
  NET_RAW: {
    description: "CAP_NET_RAW — send raw packets; enables ARP poisoning on the shared network.",
    weight: 0.6,
  },
  DAC_READ_SEARCH: {
    description: "CAP_DAC_READ_SEARCH — bypass file read permissions; read every file on mounted volumes.",
    weight: 0.75,
  },
  DAC_OVERRIDE: {
    description: "CAP_DAC_OVERRIDE — bypass all file permission checks.",
    weight: 0.8,
  },
};

/**
 * Keys whose presence with POSITIVE values compensates for some sandbox
 * defeats (but NEVER for privileged: true — lethal edge case #1).
 */
export const COMPENSATING_CONTROL_KEYS: Record<string, { description: string }> = {
  runAsNonRoot: { description: "runAsNonRoot: true enforces non-root execution." },
  readOnlyRootFilesystem: { description: "readOnlyRootFilesystem: true prevents runtime file writes to /." },
  "no-new-privileges": { description: "no-new-privileges prevents setuid escalation." },
};
