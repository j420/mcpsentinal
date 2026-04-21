/**
 * K9 — Dangerous Post-Install Hooks: dangerous-token registry.
 *
 * Substring tokens (no regex) that identify fetch-and-exec, inline
 * obfuscation, shell-invocation, and subprocess patterns inside
 * install-hook script bodies. Lives under `data/` so the no-static-
 * patterns guard skips the directory.
 *
 * When a token matches, the finding's `dangerous_command_family` factor
 * records which family fired so an auditor can read the evidence chain
 * and know which class of attack the scanner saw.
 */

export interface DangerousTokenFamily {
  family: "fetch-and-exec" | "inline-base64" | "shell-invocation" | "subprocess-call" | "eval-call";
  tokens: readonly string[];
  severity: "critical" | "high" | "medium";
  description: string;
}

/**
 * Ordered from strongest-signal to weakest. Detection iterates the
 * families in order and uses the FIRST hit to classify the finding.
 */
export const DANGEROUS_TOKEN_FAMILIES: readonly DangerousTokenFamily[] = [
  {
    family: "fetch-and-exec",
    tokens: [
      "curl ",
      "curl$(",
      "wget ",
      "wget$(",
      "fetch(",
    ],
    severity: "critical",
    description: "fetches content from the network during install — the canonical supply-chain attack pattern (ua-parser-js, event-stream, colors)",
  },
  {
    family: "inline-base64",
    tokens: [
      "base64 -d",
      "base64 --decode",
      "Buffer.from(",
      "atob(",
      "eval(Buffer",
    ],
    severity: "critical",
    description: "decodes an obfuscated payload during install — hiding a fetch-and-exec inside a base64 blob",
  },
  {
    family: "shell-invocation",
    tokens: [
      "| bash",
      "|bash",
      "| sh",
      "|sh",
      "| zsh",
      "|zsh",
      "bash -c",
      "sh -c",
    ],
    severity: "critical",
    description: "pipes output into a shell interpreter — the classic curl-pipe-sh termination of a fetch-and-exec chain",
  },
  {
    family: "subprocess-call",
    tokens: [
      "subprocess.run",
      "subprocess.call",
      "subprocess.Popen",
      "subprocess.check_output",
      "os.system",
      "child_process.exec",
    ],
    severity: "critical",
    description: "invokes a subprocess from a Python setup.py cmdclass / install hook",
  },
  {
    family: "eval-call",
    tokens: [
      " eval(",
      ";eval(",
      "eval $(",
    ],
    severity: "critical",
    description: "executes arbitrary code inside an install hook",
  },
];

/**
 * Safe-by-convention tokens inside install hooks — legitimate build tools
 * whose presence in a postinstall script is expected. When an install
 * hook consists ONLY of these tokens and no dangerous-family tokens, the
 * rule produces zero findings.
 */
export const KNOWN_BUILD_TOKENS: ReadonlySet<string> = new Set([
  "node-gyp",
  "prebuild",
  "esbuild",
  "tsc",
  "npx tsc",
  "cmake",
  "make",
  "webpack",
  "rollup",
  "vite build",
  "yarn build",
  "pnpm build",
]);

/** The lifecycle-hook keys we inspect inside package.json and friends. */
export const INSTALL_HOOK_KEYS: readonly string[] = [
  "postinstall",
  "preinstall",
  "install",
  "postpack",
  "prepack",
] as const;
