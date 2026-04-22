/**
 * P7 — sensitive host-path vocabulary.
 *
 * Each entry is a path prefix whose presence in a volume / mount /
 * hostPath context is a finding. Matching is a path-prefix match
 * with the path-boundary rules described in isPathBoundary() in
 * gather.ts.
 */

export type PathCategory =
  | "root"
  | "etc"
  | "root-home"
  | "proc"
  | "sys"
  | "dev"
  | "var-run"
  | "ssh-keys"
  | "kubelet-credentials"
  | "kube-config";

export interface SensitivePath {
  id: string;
  path: string;
  category: PathCategory;
  description: string;
  weight: number;
  /** Whether the path represents full host root (elevated concern). */
  isRootFilesystem: boolean;
}

export const SENSITIVE_PATHS: Record<string, SensitivePath> = {
  "host-root": {
    id: "host-root",
    path: "/",
    category: "root",
    description: "Full host root filesystem mount — exposes every file on the node.",
    weight: 1.0,
    isRootFilesystem: true,
  },
  "host-etc": {
    id: "host-etc",
    path: "/etc",
    category: "etc",
    description: "Host /etc — exposes systemd unit files, kubeconfig, SSH host keys, shadow file.",
    weight: 0.95,
    isRootFilesystem: false,
  },
  "host-root-home": {
    id: "host-root-home",
    path: "/root",
    category: "root-home",
    description: "/root home directory — exposes root user credentials, history, SSH keys.",
    weight: 0.95,
    isRootFilesystem: false,
  },
  "host-proc": {
    id: "host-proc",
    path: "/proc",
    category: "proc",
    description: "/proc — exposes process memory, kernel parameters, kcore if readable.",
    weight: 0.9,
    isRootFilesystem: false,
  },
  "host-sys": {
    id: "host-sys",
    path: "/sys",
    category: "sys",
    description: "/sys — exposes cgroup / sysfs / kernel subsystem controls.",
    weight: 0.85,
    isRootFilesystem: false,
  },
  "host-dev": {
    id: "host-dev",
    path: "/dev",
    category: "dev",
    description: "/dev — raw device access including disks and terminals.",
    weight: 0.85,
    isRootFilesystem: false,
  },
  "host-var-run": {
    id: "host-var-run",
    path: "/var/run",
    category: "var-run",
    description:
      "/var/run — contains the Docker socket, containerd socket, systemd control, and " +
      "kubelet pid file. Mounting this directory is equivalent to mounting /var/run/docker.sock.",
    weight: 0.95,
    isRootFilesystem: false,
  },
  "host-var-lib-kubelet": {
    id: "host-var-lib-kubelet",
    path: "/var/lib/kubelet",
    category: "kubelet-credentials",
    description:
      "/var/lib/kubelet — contains kubelet PKI material and pod service-account tokens. " +
      "Read access lets any process impersonate the node's kubelet.",
    weight: 1.0,
    isRootFilesystem: false,
  },
  "host-var-lib-kubernetes": {
    id: "host-var-lib-kubernetes",
    path: "/var/lib/kubernetes",
    category: "kubelet-credentials",
    description:
      "/var/lib/kubernetes — contains admin.conf / controller-manager credentials.",
    weight: 1.0,
    isRootFilesystem: false,
  },
  "host-ssh-keys": {
    id: "host-ssh-keys",
    path: "/.ssh",
    category: "ssh-keys",
    description:
      "SSH keys directory — reveals authentication material for every upstream SSH target. " +
      "Matches both /root/.ssh and ~/.ssh forms.",
    weight: 0.95,
    isRootFilesystem: false,
  },
  "host-kube-config": {
    id: "host-kube-config",
    path: "/.kube",
    category: "kube-config",
    description:
      "~/.kube / /root/.kube — contains cluster admin kubeconfig with impersonation tokens.",
    weight: 1.0,
    isRootFilesystem: false,
  },
};

/** Tokens indicating a volume / mount context (shared with P1). */
export const MOUNT_CONTEXT_TOKENS: Record<string, { description: string }> = {
  volumes: { description: "docker-compose / k8s volumes: declaration" },
  volumemounts: { description: "k8s volumeMounts array" },
  hostpath: { description: "k8s hostPath volume source" },
  mount: { description: "generic mount / docker --mount / bind mount" },
  bind: { description: "docker --volume / compose bind type" },
  source: { description: "docker --mount source=... field" },
  subpath: { description: "k8s volumeMounts subPath field" },
};
