/**
 * P6 — LD_PRELOAD / shared-library / process-memory hijack vocabulary.
 *
 * Each entry defines one variant. Matching is case-sensitive for
 * Linux env variables (LD_PRELOAD, LD_AUDIT) and file paths; case-
 * insensitive match is intentionally avoided to prevent matches on
 * unrelated identifiers like `ld_preload_docs`.
 */

export type HijackVariant =
  | "ld-preload-env"
  | "ld-so-preload-file"
  | "dyld-insert-libraries"
  | "dlopen-variable"
  | "proc-pid-mem"
  | "ptrace-attach";

export type MatchKind =
  | "kv-nonempty"    // key=value where value is non-empty (LD_PRELOAD=/path.so)
  | "path-write"     // write / echo / tee to a specific path
  | "function-call"  // code-level function reference
  | "literal-path";  // path literal token

export interface HijackPattern {
  id: HijackVariant;
  key: string;
  matchKind: MatchKind;
  /** Weight contributes to base confidence factor. */
  weight: number;
  /** Whether this variant allows a variable (attacker-controlled) target. */
  variablePathPossible: boolean;
  description: string;
}

export const HIJACK_PATTERNS: Record<HijackVariant, HijackPattern> = {
  "ld-preload-env": {
    id: "ld-preload-env",
    key: "LD_PRELOAD",
    matchKind: "kv-nonempty",
    weight: 0.95,
    variablePathPossible: true,
    description:
      "LD_PRELOAD env assignment — the linker will load the specified shared " +
      "object before all others, intercepting every libc call in the target " +
      "process.",
  },
  "ld-so-preload-file": {
    id: "ld-so-preload-file",
    key: "/etc/ld.so.preload",
    matchKind: "literal-path",
    weight: 1.0,
    variablePathPossible: true,
    description:
      "/etc/ld.so.preload write — affects every binary on the system including " +
      "sshd / kubelet / containerd. Strictly more dangerous than the LD_PRELOAD " +
      "env form because it is system-wide.",
  },
  "dyld-insert-libraries": {
    id: "dyld-insert-libraries",
    key: "DYLD_INSERT_LIBRARIES",
    matchKind: "kv-nonempty",
    weight: 0.9,
    variablePathPossible: true,
    description:
      "macOS DYLD_INSERT_LIBRARIES — equivalent of LD_PRELOAD on Darwin. " +
      "Systems integrity protection restricts this for system binaries; " +
      "userspace binaries are unaffected.",
  },
  "dlopen-variable": {
    id: "dlopen-variable",
    key: "dlopen",
    matchKind: "function-call",
    weight: 0.75,
    variablePathPossible: true,
    description:
      "dlopen() with a variable path — dynamic load of a shared object from " +
      "a caller-controlled path. Distinct from hard-coded libssl / libcrypto " +
      "loads, which are legitimate.",
  },
  "proc-pid-mem": {
    id: "proc-pid-mem",
    key: "/proc/",
    matchKind: "literal-path",
    weight: 0.9,
    variablePathPossible: false,
    description:
      "/proc/PID/mem write — direct process memory injection. Distinct " +
      "primitive from LD_PRELOAD but same architectural class.",
  },
  "ptrace-attach": {
    id: "ptrace-attach",
    key: "PTRACE_ATTACH",
    matchKind: "literal-path",
    weight: 0.8,
    variablePathPossible: false,
    description:
      "ptrace(PTRACE_ATTACH, ...) — attach to another process to read/write " +
      "its memory space. Legitimate for debuggers; suspicious when combined " +
      "with inline syscall emission.",
  },
};

/** Tokens that mark a write (Dockerfile RUN, shell script). */
export const PATH_WRITE_TOKENS: Record<string, { description: string }> = {
  echo: { description: "echo <value> > <path>" },
  tee: { description: "tee <path>" },
  "cat >": { description: "cat > <path>" },
  "printf ": { description: "printf ... > <path>" },
  "chmod +x": { description: "chmod + write combination" },
};
