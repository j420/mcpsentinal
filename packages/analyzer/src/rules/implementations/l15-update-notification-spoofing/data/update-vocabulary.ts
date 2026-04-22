/**
 * L15 update-notification-spoofing vocabulary.
 *
 * Typed Records replacing 9 regex literals from the legacy detector.
 * Each signal is either an "update-notification anchor" or an
 * "install-command anchor"; the finding fires when BOTH coexist in
 * the same string literal.
 */

export interface UpdateSignal {
  readonly anchor_tokens: readonly string[];
  readonly qualifier_tokens: readonly string[];
  readonly proximity: number;
  readonly desc: string;
}

export const NOTIFICATION_SIGNALS: Readonly<Record<string, UpdateSignal>> = {
  "update-available": {
    anchor_tokens: ["update", "upgrade"],
    qualifier_tokens: ["available", "required", "needed", "recommended"],
    proximity: 2,
    desc: "update availability announcement",
  },
  "new-version": {
    anchor_tokens: ["new", "newer", "latest"],
    qualifier_tokens: ["version"],
    proximity: 1,
    desc: "new-version announcement",
  },
  "update-imperative": {
    anchor_tokens: ["please", "must", "should"],
    qualifier_tokens: ["update", "upgrade", "install"],
    proximity: 2,
    desc: "update imperative",
  },
};

/** Package-manager install commands (token sequences). */
export const INSTALL_COMMAND_ANCHORS: readonly string[] = [
  "npm",
  "pnpm",
  "yarn",
  "pip",
  "brew",
];

export const INSTALL_COMMAND_VERBS: readonly string[] = [
  "install",
  "add",
];

/** "curl ... | bash" pipe-to-shell sign. */
export const PIPE_SHELL_TOKENS: readonly string[] = [
  "curl",
  "wget",
];

export const SHELL_EXECUTORS: readonly string[] = [
  "bash",
  "sh",
];

/** Legitimate update-check idioms that DISQUALIFY the finding when present
 *  in the enclosing function scope. */
export const LEGITIMATE_UPDATE_IDIOMS: readonly string[] = [
  "dependabot",
  "renovate",
  "greenkeeper",
  "semver",
  "update-notifier",
];
