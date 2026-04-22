/**
 * B7 — typed catalogue of dangerous default patterns.
 */

export interface DestructiveBoolSpec {
  label: string;
  rationale: string;
}

/** Parameter names where default=true is inherently dangerous. */
export const DESTRUCTIVE_BOOL_PARAMS: Readonly<Record<string, DestructiveBoolSpec>> = {
  overwrite: { label: "overwrite: true", rationale: "default overwrite wipes existing data silently" },
  recursive: { label: "recursive: true", rationale: "default recursion expands blast radius" },
  force: { label: "force: true", rationale: "default force bypasses safety checks" },
  allow_all: { label: "allow_all: true", rationale: "default allow_all grants maximum scope" },
  disable_ssl_verify: { label: "disable_ssl_verify: true", rationale: "default disables TLS verification" },
  insecure: { label: "insecure: true", rationale: "default enables insecure transport" },
  skip_validation: { label: "skip_validation: true", rationale: "default bypasses input validation" },
  delete: { label: "delete: true", rationale: "default performs destructive delete" },
  remove: { label: "remove: true", rationale: "default performs destructive remove" },
};

/** Parameter names that should NOT default to permissive values. */
export const READ_ONLY_FLAG_NAMES: Readonly<Record<string, DestructiveBoolSpec>> = {
  read_only: { label: "read_only: false", rationale: "read-only flag defaulting to false yields write access" },
};

export interface PathDangerSpec {
  value: string;
  label: string;
  rationale: string;
}

/** Dangerous string defaults for path/glob parameters. */
export const DANGEROUS_STRING_DEFAULTS: readonly PathDangerSpec[] = [
  { value: "/", label: "root path default", rationale: "root filesystem path by default" },
  { value: "*", label: "wildcard default", rationale: "wildcard matches everything by default" },
  { value: "**", label: "recursive wildcard default", rationale: "recursive glob matches every descendant" },
];

/** Param name tokens that indicate a path/dir parameter. */
export const PATH_PARAM_TOKENS: ReadonlySet<string> = new Set([
  "path", "dir", "directory", "folder", "glob",
]);
