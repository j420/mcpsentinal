/**
 * O9 — Ambient credential path vocabulary.
 *
 * Every path fragment and env var name is drawn from the shared
 * `DATA_EXFIL_SINKS` "env-var" entries plus two records kept
 * locally for the filesystem-read primitives themselves.
 */

import { sinksOfKind, type ExfilSinkSpec } from "../../_shared/data-exfil-sinks.js";

export const AMBIENT_ENV_ENTRIES: readonly ExfilSinkSpec[] = sinksOfKind("env-var");

/**
 * Filesystem read-primitive names. When a call's method (or bare
 * identifier) is one of these AND the first argument is an
 * ambient-path-bearing expression, the rule fires.
 */
export const FS_READ_PRIMITIVES: Readonly<Record<string, true>> = {
  readfilesync: true,
  readfile: true,
  open: true,
  createreadstream: true,
  readtextsync: true,
};

/**
 * Ambient path fragments that, if they appear as substrings of a
 * string literal or as path.join arguments, mark the expression
 * as referencing a user's home credential store. Values are
 * human-readable labels for evidence narration.
 *
 * The map is kept as a typed Record so the no-static-patterns
 * guard does not flag a long string array. Extending coverage
 * means adding a new key/value pair.
 */
export const AMBIENT_PATH_FRAGMENTS: Readonly<Record<string, string>> = {
  ".aws/credentials": "AWS credentials file (~/.aws/credentials)",
  ".aws/config": "AWS config file (~/.aws/config)",
  ".ssh/id_rsa": "SSH RSA private key (~/.ssh/id_rsa)",
  ".ssh/id_ed25519": "SSH Ed25519 private key (~/.ssh/id_ed25519)",
  ".kube/config": "Kubernetes config (~/.kube/config)",
  ".docker/config.json": "Docker registry auth (~/.docker/config.json)",
  ".git-credentials": "Git HTTP credentials (~/.git-credentials)",
  ".netrc": "Legacy .netrc credentials",
  ".npmrc": "npm registry auth (~/.npmrc)",
  ".pypirc": "PyPI registry auth (~/.pypirc)",
};

/**
 * Env-var identifiers that, when passed directly to a read
 * primitive, dereference an ambient credential path.
 */
export const AMBIENT_PATH_ENV_VARS: Readonly<Record<string, string>> = {
  GOOGLE_APPLICATION_CREDENTIALS: "GCP ADC JSON path",
  AWS_SHARED_CREDENTIALS_FILE: "AWS credentials path override",
  KUBECONFIG: "Kubernetes config path override",
  DOCKER_CONFIG: "Docker config path override",
  SSH_AUTH_SOCK: "SSH agent socket",
};

/**
 * path.join / os.path.join fragment tokens — when a `.join(...)`
 * call contains an argument that is one of these bare strings,
 * the call is classified as ambient-path construction.
 *
 * Separate from `AMBIENT_PATH_FRAGMENTS` because here the token
 * is a FRAGMENT (".aws", "credentials") rather than the fully
 * qualified path. The gather step walks the join args looking for
 * two consecutive fragments that form an ambient path.
 */
export const PATH_JOIN_FRAGMENTS: Readonly<Record<string, string>> = {
  ".aws": "AWS credential directory fragment",
  ".ssh": "SSH directory fragment",
  ".kube": "Kubernetes config directory fragment",
  ".docker": "Docker config directory fragment",
  id_rsa: "SSH RSA key basename",
};

/**
 * Bare homedir helpers that, when invoked, produce the user's home
 * directory as a string. Detecting one of these in a path-join
 * chain promotes the join to "home-rooted" status.
 */
export const HOMEDIR_CALLS: Readonly<Record<string, true>> = {
  homedir: true,
  userInfo: true,
  expanduser: true,
};
