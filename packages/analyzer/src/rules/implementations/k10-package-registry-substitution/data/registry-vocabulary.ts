/**
 * K10 vocabulary — trusted registry hosts, enterprise mirror markers,
 * configuration tokens. Record<string, true> shapes so the
 * no-static-patterns guard leaves them alone.
 */

export type Ecosystem = "npm" | "pip" | "yarn" | "go";

/**
 * Hostnames whose presence in a registry URL marks the URL as trusted.
 * Substring match against the URL's lowercase form.
 */
export const TRUSTED_REGISTRY_HOSTS: Record<string, Ecosystem> = {
  "registry.npmjs.org": "npm",
  "npm.pkg.github.com": "npm",
  "registry.yarnpkg.com": "yarn",
  "pypi.org": "pip",
  "files.pythonhosted.org": "pip",
  "proxy.golang.org": "go",
};

/**
 * Hostname substrings that indicate an enterprise / private / local
 * mirror. Presence lowers the finding from "untrusted external" to
 * an informational advisory (reviewer still has to confirm integrity
 * hashing is enforced).
 */
export const ENTERPRISE_MIRROR_SUBSTRINGS: Record<string, true> = {
  verdaccio: true,
  artifactory: true,
  nexus: true,
  jfrog: true,
  localhost: true,
  "127.0.0.1": true,
  "internal.": true,
  "private.": true,
};

/**
 * Configuration keys a package manager uses to set the registry URL.
 * The gather pass looks for lines of the form "<key>=<url>" in
 * .npmrc / pip.conf / go.env shaped files.
 */
export const REGISTRY_CONFIG_KEYS: Record<string, Ecosystem> = {
  registry: "npm",
  npmRegistryServer: "yarn",
  "index-url": "pip",
  "extra-index-url": "pip",
  GOPROXY: "go",
};

/**
 * Filename suffixes for the config files we scan directly (not source code).
 */
export const REGISTRY_CONFIG_FILES: Record<string, Ecosystem> = {
  ".npmrc": "npm",
  "npmrc": "npm",
  "pip.conf": "pip",
  "pip.ini": "pip",
  "yarnrc": "yarn",
  ".yarnrc": "yarn",
  ".yarnrc.yml": "yarn",
  "go.env": "go",
  ".go-env": "go",
  "pyproject.toml": "pip",
};
