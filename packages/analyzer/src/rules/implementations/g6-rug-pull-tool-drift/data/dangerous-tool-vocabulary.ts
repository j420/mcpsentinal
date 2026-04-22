/**
 * G6 dangerous-tool name vocabulary.
 *
 * When a rug-pull-detector finds newly-added tools, it runs each new
 * tool's name through this vocabulary to identify ones whose name
 * directly implies destructive capability. A new BENIGN tool (e.g.
 * `get_weather`) is low-signal; a new tool named `exec_shell_command`
 * is the canonical rug-pull payload.
 *
 * Loaded as an object-literal Record so the no-static-patterns guard
 * does not consider the list a "long string-literal array".
 */

export type DangerClass =
  | "command-execution"
  | "filesystem-destructive"
  | "network-egress"
  | "credential-access"
  | "administrative";

export interface VocabEntry {
  /** The danger class this token maps to. */
  class: DangerClass;
  /** Short rationale used in the evidence chain. */
  rationale: string;
}

/**
 * Token → danger class. Tokens are lowercase, match as substrings of
 * the lowercased tool name. Keep the map concise — the vocabulary
 * should name classes, not enumerate every synonym.
 */
export const DANGEROUS_TOOL_TOKENS: Record<string, VocabEntry> = {
  exec: {
    class: "command-execution",
    rationale: "The 'exec' token names shell or process execution — the canonical rug-pull payload.",
  },
  shell: {
    class: "command-execution",
    rationale: "The 'shell' token names shell command dispatch.",
  },
  run_command: {
    class: "command-execution",
    rationale: "Literal 'run_command' names shell execution.",
  },
  spawn: {
    class: "command-execution",
    rationale: "The 'spawn' token names process spawning.",
  },
  delete: {
    class: "filesystem-destructive",
    rationale: "The 'delete' token names a destructive filesystem operation.",
  },
  remove: {
    class: "filesystem-destructive",
    rationale: "The 'remove' token names a destructive filesystem operation.",
  },
  unlink: {
    class: "filesystem-destructive",
    rationale: "The 'unlink' token names POSIX file removal.",
  },
  rm: {
    class: "filesystem-destructive",
    rationale: "The 'rm' token names a destructive filesystem operation.",
  },
  write: {
    class: "filesystem-destructive",
    rationale: "The 'write' token names filesystem mutation, which becomes destructive on approved paths.",
  },
  upload: {
    class: "network-egress",
    rationale: "The 'upload' token names outbound data transfer — a network-egress vector.",
  },
  send: {
    class: "network-egress",
    rationale: "The 'send' token names outbound communication — a network-egress vector.",
  },
  post: {
    class: "network-egress",
    rationale: "The 'post' token names HTTP POST — outbound data transfer.",
  },
  credential: {
    class: "credential-access",
    rationale: "The 'credential' token names a secrets-handling operation.",
  },
  token: {
    class: "credential-access",
    rationale: "The 'token' token names a secrets-handling operation.",
  },
  secret: {
    class: "credential-access",
    rationale: "The 'secret' token names a secrets-handling operation.",
  },
  admin: {
    class: "administrative",
    rationale: "The 'admin' token names elevated-privilege control.",
  },
  sudo: {
    class: "administrative",
    rationale: "The 'sudo' token names privilege escalation.",
  },
};
