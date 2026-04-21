/**
 * D3 — Legitimate-fork allowlist.
 *
 * Some package names are within Damerau-Levenshtein distance 3 of a
 * popular target yet are legitimate forks, ports, or ecosystem siblings:
 *
 *   - `lodash-es` is an official ES-module fork of `lodash`
 *   - `@types/lodash` is the community TypeScript declarations
 *   - `pino-http` is an accessory in the pino family
 *
 * Entries here are suppressed from similarity findings entirely. The
 * `shadows` field is the target the fork is a legitimate variant of,
 * kept for audit traceability.
 *
 * Object-literal (Record) shape so the no-static-patterns guard leaves
 * it alone.
 */

export interface LegitimateFork {
  /** The package the name is a legitimate fork/variant of. */
  shadows: string;
}

export const LEGITIMATE_FORKS: Record<string, LegitimateFork> = {
  "lodash-es": { shadows: "lodash" },
  "lodash.debounce": { shadows: "lodash" },
  "lodash.clonedeep": { shadows: "lodash" },
  "@types/lodash": { shadows: "lodash" },
  "@types/node": { shadows: "node" },
  "@types/react": { shadows: "react" },
  "pino-http": { shadows: "pino" },
  "pino-pretty": { shadows: "pino" },
  "winston-daily-rotate-file": { shadows: "winston" },
  "winston-transport": { shadows: "winston" },
  "@storybook/react": { shadows: "react" },
  "react-dom": { shadows: "react" },
  "react-router": { shadows: "react" },
  "vue-router": { shadows: "vue" },
  "express-session": { shadows: "express" },
  "angular-core": { shadows: "angular" },
  "angular-cli": { shadows: "angular" },
  "next-auth": { shadows: "next" },
  "@nestjs/common": { shadows: "nestjs" },
  "svelte-kit": { shadows: "svelte" },
  "requests-oauthlib": { shadows: "requests" },
  "requests-toolbelt": { shadows: "requests" },
  "pydantic-settings": { shadows: "pydantic" },
  "flask-login": { shadows: "flask" },
  "flask-restful": { shadows: "flask" },
  "django-rest-framework": { shadows: "django" },
  "djangorestframework": { shadows: "django" },
  "fastapi-utils": { shadows: "fastapi" },
  "typescript-eslint": { shadows: "eslint" },
  "eslint-config-prettier": { shadows: "eslint" },
  "eslint-plugin-react": { shadows: "eslint" },
};

/**
 * Structural tokens that, when appended to a candidate name, reliably
 * indicate a legitimate fork or variant. Applied only when the
 * candidate's raw Levenshtein distance to the target would otherwise
 * fire — shifts such cases out of the typosquat cohort.
 *
 * ≤ 5 entries so the guard leaves this literal alone.
 */
export const LEGITIMATE_SUFFIX_TOKENS: readonly string[] = [
  "-es",
  "-fork",
  "-pro",
  "-community",
  "-unofficial",
];

/**
 * Structural prefixes indicating a legitimate type-definition or
 * namespaced re-export, applied the same way as LEGITIMATE_SUFFIX_TOKENS.
 *
 * ≤ 5 entries.
 */
export const LEGITIMATE_PREFIX_TOKENS: readonly string[] = [
  "@types/",
  "types-",
];
