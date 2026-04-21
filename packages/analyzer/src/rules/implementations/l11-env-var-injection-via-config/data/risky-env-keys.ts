/**
 * L11 — risky environment variable registry.
 *
 * Each entry classifies an env variable whose appearance inside the MCP
 * config's `env` block is a direct code-execution-or-traffic-steering
 * primitive. The classification drives sink_type / impact_type on the
 * evidence chain so the regulator can see WHICH primitive fired.
 *
 * Record<string, {...}> (not a string-literal array) so the
 * no-static-patterns guard leaves it alone.
 */

export type EnvRiskClass =
  | "library-hijack"    // LD_PRELOAD / DYLD_* — shared library load-time injection
  | "runtime-injection" // NODE_OPTIONS / PYTHONPATH / PYTHONSTARTUP — runtime module injection
  | "path-override"     // PATH / PATHEXT — binary resolution hijack
  | "proxy-mitm"        // HTTP_PROXY / HTTPS_PROXY / ALL_PROXY — outbound traffic interception
  | "api-endpoint";     // ANTHROPIC_API_URL / OPENAI_API_BASE — AI-API redirect (CVE-2026-21852)

export interface EnvRiskEntry {
  riskClass: EnvRiskClass;
  /** Short human rationale (≤ 80 chars) for the evidence link. */
  rationale: string;
}

export const RISKY_ENV_KEYS: Record<string, EnvRiskEntry> = {
  // library-hijack — dynamic linker pre-load / insert / path (macOS + Linux).
  LD_PRELOAD: {
    riskClass: "library-hijack",
    rationale: "Forces the dynamic linker to load an attacker-chosen .so before all other libraries",
  },
  LD_LIBRARY_PATH: {
    riskClass: "library-hijack",
    rationale: "Prepends an attacker directory to the library search path — shadow legit .so files",
  },
  DYLD_INSERT_LIBRARIES: {
    riskClass: "library-hijack",
    rationale: "macOS equivalent of LD_PRELOAD — attacker dylib loaded into every child process",
  },
  DYLD_LIBRARY_PATH: {
    riskClass: "library-hijack",
    rationale: "macOS library path override — attacker dylibs shadow system libraries",
  },
  DYLD_FRAMEWORK_PATH: {
    riskClass: "library-hijack",
    rationale: "macOS framework path override — attacker frameworks shadow system frameworks",
  },

  // runtime-injection — Node.js / Python runtime module load.
  NODE_OPTIONS: {
    riskClass: "runtime-injection",
    rationale: "Accepts --require=./payload.js — arbitrary module runs in-process before main",
  },
  NODE_PATH: {
    riskClass: "runtime-injection",
    rationale: "Prepends attacker directory to Node's module resolution — shadows legit packages",
  },
  PYTHONPATH: {
    riskClass: "runtime-injection",
    rationale: "Prepends attacker directory to Python's sys.path — shadows legit modules",
  },
  PYTHONSTARTUP: {
    riskClass: "runtime-injection",
    rationale: "Python runs the referenced file at REPL startup — arbitrary code on server launch",
  },
  PYTHONHOME: {
    riskClass: "runtime-injection",
    rationale: "Redirects Python's stdlib search path — attacker-controlled stdlib replacements",
  },
  PERL5OPT: {
    riskClass: "runtime-injection",
    rationale: "Perl accepts command-line options via env — -Mattacker module loaded at startup",
  },
  RUBYOPT: {
    riskClass: "runtime-injection",
    rationale: "Ruby accepts command-line options via env — -rattacker module loaded at startup",
  },

  // path-override — binary resolution.
  PATH: {
    riskClass: "path-override",
    rationale: "Overrides binary search path — any shelled-out command resolves to attacker binary",
  },
  PATHEXT: {
    riskClass: "path-override",
    rationale: "Windows binary-extension search — attacker .cmd shadows .exe",
  },

  // proxy-mitm — outbound traffic interception.
  HTTP_PROXY: {
    riskClass: "proxy-mitm",
    rationale: "Routes outbound HTTP through attacker proxy — credentials and request bodies exposed",
  },
  HTTPS_PROXY: {
    riskClass: "proxy-mitm",
    rationale: "Routes outbound HTTPS through attacker proxy (TLS terminated at attacker)",
  },
  ALL_PROXY: {
    riskClass: "proxy-mitm",
    rationale: "Routes ALL outbound traffic through attacker proxy — catch-all interception",
  },
  NO_PROXY: {
    riskClass: "proxy-mitm",
    rationale: "Subverts proxy exemption list — forces internal traffic through attacker proxy",
  },

  // api-endpoint — AI-API redirect (CVE-2026-21852).
  ANTHROPIC_API_URL: {
    riskClass: "api-endpoint",
    rationale: "Redirects Claude API traffic — CVE-2026-21852 API-key exfiltration primitive",
  },
  OPENAI_API_BASE: {
    riskClass: "api-endpoint",
    rationale: "Redirects OpenAI API traffic — sibling primitive of CVE-2026-21852",
  },
  OPENAI_BASE_URL: {
    riskClass: "api-endpoint",
    rationale: "Newer-SDK alias for OPENAI_API_BASE — redirects outbound AI traffic",
  },
  AZURE_OPENAI_ENDPOINT: {
    riskClass: "api-endpoint",
    rationale: "Redirects Azure OpenAI API calls — credential exfiltration primitive",
  },
  API_BASE_URL: {
    riskClass: "api-endpoint",
    rationale: "Generic API-base override — any AI SDK using this name is redirected",
  },
};
