/**
 * P1 — canonical container-runtime socket registry.
 *
 * Each entry is a host-side socket path the rule flags when referenced
 * in a volume / mount / bind context. The table is exhaustive across
 * Docker, containerd, cri-o, and podman — adding a new runtime means
 * adding a row here, never adding a regex.
 */

export type SocketRuntime = "docker" | "containerd" | "crio" | "podman";

export interface SocketPathSpec {
  id: string;
  runtime: SocketRuntime;
  /** Host-side path — case-sensitive, matched as a whole-token boundary. */
  path: string;
  description: string;
  weight: number;
}

export const SOCKET_PATHS: Record<string, SocketPathSpec> = {
  "docker-var-run": {
    id: "docker-var-run",
    runtime: "docker",
    path: "/var/run/docker.sock",
    description: "Docker daemon Unix socket at /var/run/docker.sock.",
    weight: 1.0,
  },
  "docker-run": {
    id: "docker-run",
    runtime: "docker",
    path: "/run/docker.sock",
    description: "Docker daemon Unix socket at /run/docker.sock (systemd layout).",
    weight: 1.0,
  },
  "containerd-var-run": {
    id: "containerd-var-run",
    runtime: "containerd",
    path: "/var/run/containerd/containerd.sock",
    description: "containerd runtime socket — grants the same create/exec primitive as docker.sock.",
    weight: 1.0,
  },
  "containerd-run": {
    id: "containerd-run",
    runtime: "containerd",
    path: "/run/containerd/containerd.sock",
    description: "containerd runtime socket (systemd layout).",
    weight: 1.0,
  },
  "crio-var-run": {
    id: "crio-var-run",
    runtime: "crio",
    path: "/var/run/crio/crio.sock",
    description: "CRI-O runtime socket.",
    weight: 1.0,
  },
  "podman-run": {
    id: "podman-run",
    runtime: "podman",
    path: "/run/podman/podman.sock",
    description: "Podman API socket.",
    weight: 1.0,
  },
};

/** Tokens indicating a mount / volume / bind context on the same line or nearby. */
export const MOUNT_CONTEXT_TOKENS: Record<string, { description: string }> = {
  volumes: { description: "top-level compose/k8s volumes: declaration" },
  volumemounts: { description: "k8s volumeMounts array" },
  hostpath: { description: "k8s hostPath volume source" },
  mount: { description: "generic mount / docker --mount / bind mount" },
  bind: { description: "docker --volume / compose bind type" },
  source: { description: "docker --mount source=... field" },
};

/**
 * Basename fragments that indicate a socket even if the full path was
 * split across keys (subPath trick). If a line contains ".sock" AND one
 * of these fragments, the rule treats the volume context as a socket
 * reference.
 */
export const SOCKET_BASENAME_FRAGMENTS: Record<string, { description: string }> = {
  "docker.sock": { description: "docker.sock basename" },
  "containerd.sock": { description: "containerd.sock basename" },
  "crio.sock": { description: "crio.sock basename" },
  "podman.sock": { description: "podman.sock basename" },
};
