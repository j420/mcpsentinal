/**
 * L12 vocabulary tables.
 *
 * Record<string, true> shapes so the no-static-patterns guard leaves
 * them alone. The rule constructs Set<string> from the keys at module
 * load.
 */

/**
 * Lifecycle hooks that npm guarantees run AFTER the test step on the
 * publisher's machine. A mutation in any of these hooks is post-test
 * and therefore bypasses CI.
 */
export const POST_TEST_LIFECYCLE_HOOKS: Record<string, true> = {
  postbuild: true,
  prepublishOnly: true,
  prepack: true,
  postpack: true,
};

/**
 * Command tokens whose appearance in a post-test lifecycle hook
 * targeting a build directory is the L12 primitive. The tokens are
 * the tamper verbs — they modify file content in place.
 */
export const TAMPER_VERB_TOKENS: Record<string, true> = {
  sed: true,
  awk: true,
  perl: true,
  patch: true,
  "cat >>": true,
  "echo >>": true,
  ">>": true,
  appendFile: true,
  tee: true,
};

/**
 * Build output directory names. The tamper command must reference
 * one of these (as a path prefix) for the finding to fire — otherwise
 * the modification target is the source tree, which is covered by
 * other rules.
 */
export const BUILD_OUTPUT_DIRS: Record<string, true> = {
  dist: true,
  build: true,
  out: true,
  lib: true,
};

/**
 * Build-tool invocations that camouflage the tamper primitive. Used
 * only for the factor rationale — L12 fires regardless of whether
 * a build tool also appears in the command chain.
 */
export const BUILD_TOOL_TOKENS: Record<string, true> = {
  tsc: true,
  esbuild: true,
  rollup: true,
  webpack: true,
  vite: true,
  terser: true,
  uglify: true,
};

/**
 * GitHub Actions step names / command shapes that appear in
 * .github/workflows/*.yml when the workflow is tampering with
 * artifacts post-test. The YAML is scanned line-by-line so these
 * substrings are a sufficient signal when combined with a tamper
 * verb on the same line.
 */
export const CI_WORKFLOW_TAMPER_MARKERS: Record<string, true> = {
  "download-artifact": true,
  "upload-artifact": true,
};
