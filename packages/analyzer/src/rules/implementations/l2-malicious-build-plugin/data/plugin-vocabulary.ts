/**
 * L2 — Malicious Build Plugin: vocabularies.
 *
 * Lives under `data/` so the no-static-patterns guard skips the
 * directory. Every collection below is a typed record or a Set; zero
 * regex literals.
 */

/**
 * Names of bundler plugin hooks. A function literal attached to ANY of
 * these names inside a build-config file is a "plugin hook" whose body
 * the rule audits for dangerous APIs.
 */
export const PLUGIN_HOOK_NAMES: ReadonlySet<string> = new Set([
  "generateBundle",
  "transform",
  "load",
  "resolveId",
  "buildStart",
  "buildEnd",
  "writeBundle",
  "renderChunk",
  "onBuild",
  "setup",
]);

/**
 * Function identifiers that indicate a dangerous capability at
 * plugin-run time: spawning subprocesses, making network requests, or
 * writing to arbitrary filesystem locations.
 */
export interface DangerousApi {
  /** The exact identifier the AST detector matches. */
  name: string;
  /** Canonical family label for the evidence factor. */
  family: "command-execution" | "network-fetch" | "file-write" | "dynamic-plugin-load";
  /** Human description embedded in the verification step. */
  description: string;
}

export const DANGEROUS_APIS: Record<string, DangerousApi> = {
  exec: {
    name: "exec",
    family: "command-execution",
    description:
      "child_process.exec invokes a subprocess — build-time RCE primitive",
  },
  spawn: {
    name: "spawn",
    family: "command-execution",
    description:
      "child_process.spawn invokes a subprocess — build-time RCE primitive",
  },
  execSync: {
    name: "execSync",
    family: "command-execution",
    description:
      "child_process.execSync is the synchronous command executor — build-time RCE",
  },
  spawnSync: {
    name: "spawnSync",
    family: "command-execution",
    description:
      "child_process.spawnSync is the synchronous spawner — build-time RCE",
  },
  fork: {
    name: "fork",
    family: "command-execution",
    description:
      "child_process.fork spawns a child node process — arbitrary script execution",
  },
  fetch: {
    name: "fetch",
    family: "network-fetch",
    description:
      "global fetch() — build-time network egress; primary exfiltration channel",
  },
  axios: {
    name: "axios",
    family: "network-fetch",
    description:
      "axios HTTP client — build-time network egress; primary exfiltration channel",
  },
  got: {
    name: "got",
    family: "network-fetch",
    description:
      "got HTTP client — build-time network egress; primary exfiltration channel",
  },
  writeFile: {
    name: "writeFile",
    family: "file-write",
    description:
      "fs.writeFile — untrusted write target enables path-traversal (CVE-2026-27606)",
  },
  writeFileSync: {
    name: "writeFileSync",
    family: "file-write",
    description:
      "fs.writeFileSync — same path-traversal class (CVE-2026-27606)",
  },
  appendFileSync: {
    name: "appendFileSync",
    family: "file-write",
    description:
      "fs.appendFileSync — untrusted write target enables modification of build output outside outDir",
  },
};

/** Environment variable reads that, combined with a fetch primitive, indicate exfiltration intent. */
export const SENSITIVE_ENV_VAR_NAMES: ReadonlySet<string> = new Set([
  "NPM_TOKEN",
  "GITHUB_TOKEN",
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "DATABASE_URL",
  "PYPI_TOKEN",
]);

/**
 * Filename substrings that identify a build-config file. The rule walks
 * any source_files entry whose path contains one of these substrings.
 */
export const BUILD_CONFIG_FILE_MARKERS: readonly string[] = [
  "rollup.config",
  "vite.config",
  "webpack.config",
  "esbuild.config",
  "build.config",
] as const;

/**
 * Install-lifecycle hook keys inspected inside package.json. Kept short
 * (<=5 entries) so it is legal as an inline literal in non-data files,
 * but still declared here for consistency with K9's pattern.
 */
export const INSTALL_HOOK_KEYS: readonly string[] = [
  "postinstall",
  "preinstall",
  "install",
  "prepare",
] as const;

/** Fetch-and-exec signal substrings inside install-hook script bodies. */
export const INSTALL_HOOK_DANGER_TOKENS: readonly string[] = [
  "curl ",
  "wget ",
  "node -e ",
  "| bash",
  "| sh",
] as const;

/** Environment-gate tokens that enable the "conditional postinstall" edge case. */
export const INSTALL_HOOK_ENV_GATES: readonly string[] = [
  "$CI",
  "${CI}",
  "$GITHUB_ACTIONS",
  "process.env",
] as const;
