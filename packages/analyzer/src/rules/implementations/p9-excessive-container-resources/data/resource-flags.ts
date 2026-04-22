/**
 * P9 — canonical resource-limit flag registry.
 */

export type ResourceKind = "memory" | "cpu" | "pids" | "ulimit-nofile";

export interface ResourceKey {
  id: string;
  kind: ResourceKind;
  /** Canonical YAML / CLI key name. Match is case-insensitive. */
  key: string;
  /** Detection mode. */
  matchKind: "unlimited-sentinel" | "excessive-value" | "cli-zero";
  /** For excessive-value: threshold in the natural unit. */
  excessiveThreshold?: number;
  /** For excessive-value: the unit suffix recognised ("Gi" / "GB" / "G"). */
  excessiveUnits?: Record<string, number>;
  description: string;
  weight: number;
}

/** Units expressible for memory limits. Value = multiplier relative to bytes. */
export const MEMORY_UNITS: Record<string, number> = {
  gi: 1024 * 1024 * 1024,
  gib: 1024 * 1024 * 1024,
  gb: 1000 * 1000 * 1000,
  g: 1024 * 1024 * 1024,
};

/** Unlimited sentinel values recognised by Docker / Kubernetes. */
export const UNLIMITED_SENTINELS: Record<string, true> = {
  unlimited: true,
  "-1": true,
  infinite: true,
};

export const RESOURCE_KEYS: Record<string, ResourceKey> = {
  "memory-unlimited": {
    id: "memory-unlimited",
    kind: "memory",
    key: "memory",
    matchKind: "unlimited-sentinel",
    description: "Memory limit set to unlimited / -1.",
    weight: 0.9,
  },
  "memory-mem-limit-unlimited": {
    id: "memory-mem-limit-unlimited",
    kind: "memory",
    key: "mem_limit",
    matchKind: "unlimited-sentinel",
    description: "docker-compose mem_limit set to unlimited / -1.",
    weight: 0.9,
  },
  "memory-excessive": {
    id: "memory-excessive",
    kind: "memory",
    key: "memory",
    matchKind: "excessive-value",
    excessiveThreshold: 32,
    excessiveUnits: MEMORY_UNITS,
    description: "Memory limit > 32 Gi — likely exceeds node capacity, invites OOM-kill thrash.",
    weight: 0.55,
  },
  "cpu-unlimited": {
    id: "cpu-unlimited",
    kind: "cpu",
    key: "cpu",
    matchKind: "unlimited-sentinel",
    description: "CPU limit set to unlimited / 0.",
    weight: 0.75,
  },
  "cpu-limit-unlimited": {
    id: "cpu-limit-unlimited",
    kind: "cpu",
    key: "cpu_limit",
    matchKind: "unlimited-sentinel",
    description: "cpu_limit set to unlimited / 0.",
    weight: 0.75,
  },
  "docker-memory-zero": {
    id: "docker-memory-zero",
    kind: "memory",
    key: "--memory",
    matchKind: "cli-zero",
    description: "Docker CLI --memory=0 means unlimited memory.",
    weight: 0.9,
  },
  "docker-cpus-zero": {
    id: "docker-cpus-zero",
    kind: "cpu",
    key: "--cpus",
    matchKind: "cli-zero",
    description: "Docker CLI --cpus=0 means unlimited CPU.",
    weight: 0.8,
  },
  "pids-unlimited": {
    id: "pids-unlimited",
    kind: "pids",
    key: "pids_limit",
    matchKind: "unlimited-sentinel",
    description: "PIDs limit set to unlimited / -1 — fork-bomb vulnerability.",
    weight: 1.0,
  },
  "pids-limit-k8s-unlimited": {
    id: "pids-limit-k8s-unlimited",
    kind: "pids",
    key: "pidsLimit",
    matchKind: "unlimited-sentinel",
    description: "pidsLimit set to unlimited / -1 — fork-bomb vulnerability.",
    weight: 1.0,
  },
  "docker-pids-zero": {
    id: "docker-pids-zero",
    kind: "pids",
    key: "--pids-limit",
    matchKind: "cli-zero",
    description: "Docker CLI --pids-limit=0 or -1 means unlimited PIDs.",
    weight: 1.0,
  },
  "nofile-unlimited": {
    id: "nofile-unlimited",
    kind: "ulimit-nofile",
    key: "nofile",
    matchKind: "unlimited-sentinel",
    description: "nofile ulimit set to unlimited — fd-exhaustion DoS risk.",
    weight: 0.6,
  },
};
