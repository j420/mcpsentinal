/**
 * L5 — vocabulary tables used by the structural package-manifest parser.
 *
 * Record<string, true> shapes (not string-literal arrays) so the
 * no-static-patterns guard leaves them alone. The ruleset owns them;
 * gather.ts constructs read-only Sets from the keys at module load.
 */

/**
 * Package.json script lifecycle hooks that run on the PUBLISHER's
 * machine before the tarball is built. A mutation to package.json in
 * any of these hooks is the manifest-confusion primitive.
 */
export const PUBLISH_LIFECYCLE_HOOKS: Record<string, true> = {
  prepublish: true,
  prepublishOnly: true,
  prepack: true,
  prepare: true,
};

/**
 * Command tokens whose appearance in a prepublish script indicates the
 * script is MUTATING package.json. The rule matches any of these
 * tokens followed anywhere in the same command by the literal
 * substring `package.json` — that is the mutation-of-manifest shape.
 */
export const MANIFEST_MUTATION_TOKENS: Record<string, true> = {
  sed: true,
  awk: true,
  jq: true,
  "node -e": true,
  "node --eval": true,
  perl: true,
  mv: true,
};

/**
 * Build-tool invocations that, if present in the same command chain as
 * a mutation token, demote the finding to informational. A prepublish
 * that runs `tsc && sed -i ...` is still a finding (sed mutates), but
 * a prepublish that runs ONLY `tsc` is not.
 */
export const BUILD_TOOL_TOKENS: Record<string, true> = {
  tsc: true,
  esbuild: true,
  rollup: true,
  webpack: true,
  vite: true,
  babel: true,
  swc: true,
  terser: true,
};

/**
 * System-command names whose appearance in a package.json bin key is
 * the bin-field shadowing primitive. Curated from the ecosystem-
 * adversarial research set (2024-2025 npm hijacking incidents) and
 * extended with the MCP-relevant tools a malicious package would most
 * benefit from shadowing (node, npm, python, pip, ssh, curl, git).
 */
export const SYSTEM_COMMAND_BIN_NAMES: Record<string, true> = {
  ls: true,
  cat: true,
  grep: true,
  curl: true,
  wget: true,
  ssh: true,
  sudo: true,
  su: true,
  chmod: true,
  chown: true,
  rm: true,
  mv: true,
  cp: true,
  node: true,
  npm: true,
  npx: true,
  python: true,
  python3: true,
  pip: true,
  git: true,
  docker: true,
  kubectl: true,
  make: true,
  bash: true,
  sh: true,
  zsh: true,
};

/**
 * Filename substrings whose presence in a conditional-exports target
 * path signals a payload-shaped file. Used by the exports-divergence
 * primitive — divergence alone is benign (legitimate CJS/ESM builds
 * exist); divergence WITH a payload-shaped substring in one branch
 * is the finding.
 */
export const PAYLOAD_FILENAME_SUBSTRINGS: Record<string, true> = {
  backdoor: true,
  payload: true,
  hook: true,
  inject: true,
  hidden: true,
};

/**
 * The exports map key whose being set to `null` or `false` blocks
 * audit tools from reading the installed package.json. Listed as an
 * object so adding future blocking keys is a one-line change.
 */
export const EXPORTS_BLOCK_KEYS: Record<string, true> = {
  "./package.json": true,
};
