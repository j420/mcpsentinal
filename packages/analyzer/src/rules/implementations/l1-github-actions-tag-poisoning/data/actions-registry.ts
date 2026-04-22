/**
 * L1 — GitHub Actions Tag Poisoning: action / ref classification registry.
 *
 * Lives under `data/` so the no-static-patterns guard skips this directory.
 * Every value is a substring token or a typed record — zero regex literals.
 */

/**
 * First-party GitHub Actions published under `actions/*` and
 * `github/*`. Even for these, SHA pinning is the industry best practice,
 * but the severity of a mutable tag on `actions/checkout` is lower than
 * on a third-party Action: the tag-protection and incident-response
 * maturity of github.com/actions/* is stronger than a random Marketplace
 * publisher.
 */
export const FIRST_PARTY_ACTION_OWNERS: ReadonlySet<string> = new Set([
  "actions",
  "github",
]);

/**
 * Ref families. The classifier picks the FIRST matching family and
 * records it on the finding so an auditor can trace which substring
 * match drove the classification.
 */
export interface RefFamily {
  /** Canonical family label that appears as a confidence factor. */
  family:
    | "mutable-tag-major"
    | "mutable-tag-branch"
    | "expression-interpolated"
    | "semver-partial";
  /** Human description for the verification step. */
  description: string;
}

/**
 * Branch-style tags known to be canonical mutable heads. A ref that
 * matches ANY of these substrings (case-insensitive on the compared
 * side) is always mutable.
 */
export const MUTABLE_BRANCH_TAGS: ReadonlySet<string> = new Set([
  "main",
  "master",
  "develop",
  "dev",
  "latest",
  "edge",
  "nightly",
]);

/** Single-digit major-tag prefixes covered by the mutable-tag-major family. */
export const MUTABLE_MAJOR_PREFIXES: readonly string[] = [
  "v",
  "V",
] as const;

/**
 * Pipe-to-shell / wget-to-shell token fragments for `run:` body scans.
 * The detector calls `.includes(token)` on the run body — NO regex.
 */
export const RUN_STEP_DANGER_TOKENS: readonly string[] = [
  " | bash",
  " |bash",
  " | sh",
  " |sh",
  "| bash",
  "|bash",
  "| sh",
  "|sh",
] as const;

/**
 * Download-primitives that commonly precede a pipe-to-shell. A finding
 * is only emitted when BOTH a download primitive and a danger token
 * appear in the same `run:` body — prevents false-positives on
 * legitimate bash scripts that use pipes for filtering.
 */
export const DOWNLOAD_PRIMITIVES: readonly string[] = [
  "curl ",
  "curl$(",
  "wget ",
  "wget$(",
] as const;

/**
 * Classify a ref segment ("v5", "main", "abc123...", "${{ matrix.x }}",
 * "1.2.3"). Returns the family; null means the ref was not recognised as
 * dangerous (treated as SHA pin until proven otherwise).
 *
 * Contract: zero regex. All checks use String.prototype.includes /
 * startsWith / charCodeAt.
 */
export function classifyRef(ref: string): RefFamily | null {
  if (ref.length === 0) return null;

  // Expression-interpolated — the ref contains a template placeholder,
  // so the effective ref is only knowable at runtime.
  if (ref.includes("${{") || ref.includes("}}")) {
    return {
      family: "expression-interpolated",
      description:
        "ref is computed from a workflow expression — runtime-resolved to a potentially mutable tag",
    };
  }

  // SHA pin: exactly 40 lowercase-hex characters.
  if (isFortyLowercaseHex(ref)) return null;

  // Branch-style mutable tag.
  if (MUTABLE_BRANCH_TAGS.has(ref.toLowerCase())) {
    return {
      family: "mutable-tag-branch",
      description:
        "ref is a branch-style tag (main / master / develop / latest / edge / nightly) — mutable by definition",
    };
  }

  // Major-version tag: v1 / v5 / V10.
  for (const prefix of MUTABLE_MAJOR_PREFIXES) {
    if (ref.startsWith(prefix)) {
      const rest = ref.slice(prefix.length);
      if (rest.length > 0 && isAllDigits(rest)) {
        return {
          family: "mutable-tag-major",
          description:
            "ref is a major-version tag (v1, v5, V10) — force-pushable to a newer commit at any time",
        };
      }
    }
  }

  // Semver-ish partial: 1.2, 1.2.3 — mutable unless pinned to SHA.
  if (looksLikeSemver(ref)) {
    return {
      family: "semver-partial",
      description:
        "ref is a semver-style tag — mutable in Git; only SHA pins resist force-push tag poisoning",
    };
  }

  // Unknown shape: treat as unpinned by default (conservative).
  return {
    family: "mutable-tag-branch",
    description:
      "ref is neither a 40-hex SHA nor a recognised safe form — treated as mutable",
  };
}

function isFortyLowercaseHex(s: string): boolean {
  if (s.length !== 40) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const isDigit = c >= 0x30 && c <= 0x39;
    const isLowerHex = c >= 0x61 && c <= 0x66;
    if (!isDigit && !isLowerHex) return false;
  }
  return true;
}

function isAllDigits(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x30 || c > 0x39) return false;
  }
  return true;
}

function looksLikeSemver(s: string): boolean {
  // X or X.Y or X.Y.Z where each segment is all digits. No regex.
  const parts = s.split(".");
  if (parts.length < 1 || parts.length > 3) return false;
  for (const p of parts) {
    if (p.length === 0) return false;
    if (!isAllDigits(p)) return false;
  }
  return true;
}

/** Split a `uses:` value "owner/repo@ref" into owner, repo, ref. */
export function splitUses(value: string): { owner: string; repo: string; ref: string } | null {
  const atIdx = value.indexOf("@");
  if (atIdx < 0) return null;
  const left = value.slice(0, atIdx);
  const ref = value.slice(atIdx + 1);
  const parts = left.split("/");
  if (parts.length < 2) return null;
  const owner = parts[0];
  const repo = parts.slice(1).join("/"); // allow nested reusable workflows
  if (owner.length === 0 || repo.length === 0 || ref.length === 0) return null;
  return { owner, repo, ref };
}
