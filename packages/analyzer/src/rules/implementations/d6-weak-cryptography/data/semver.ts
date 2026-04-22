/**
 * Hand-rolled semver comparator — no regex, handles x, x.y, x.y.z with
 * optional -prerelease suffix. Strict semver input; loose manifest
 * ranges are out of scope (D6 inputs are resolved versions).
 */

export interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  /** Prerelease identifier string (without the leading '-'). */
  prerelease: string | null;
}

export function parseVersion(raw: string): ParsedVersion | null {
  if (!raw) return null;

  // Strip leading 'v' or '=' (accepted by semver.org spec).
  let s = raw;
  if (s.length > 0 && (s.charCodeAt(0) === 0x76 /* v */ || s.charCodeAt(0) === 0x3d /* = */)) {
    s = s.slice(1);
  }

  // Split on first '-' for prerelease.
  let prerelease: string | null = null;
  const dash = s.indexOf("-");
  if (dash >= 0) {
    prerelease = s.slice(dash + 1);
    s = s.slice(0, dash);
  }

  // Split on '+' for build metadata — ignored.
  const plus = s.indexOf("+");
  if (plus >= 0) s = s.slice(0, plus);

  const parts = s.split(".");
  if (parts.length === 0 || parts.length > 3) return null;

  const nums: number[] = [];
  for (const p of parts) {
    if (p.length === 0) return null;
    for (let i = 0; i < p.length; i++) {
      const code = p.charCodeAt(i);
      if (code < 0x30 || code > 0x39) return null;
    }
    const n = parseInt(p, 10);
    if (!Number.isFinite(n)) return null;
    nums.push(n);
  }

  return {
    major: nums[0] ?? 0,
    minor: nums[1] ?? 0,
    patch: nums[2] ?? 0,
    prerelease,
  };
}

/**
 * Compare two versions. Returns negative if a < b, 0 if equal, positive if a > b.
 * Prerelease < no prerelease for same x.y.z (semver spec).
 */
export function compareVersion(a: ParsedVersion, b: ParsedVersion): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;

  // Prerelease < release.
  if (a.prerelease === null && b.prerelease === null) return 0;
  if (a.prerelease === null) return 1;
  if (b.prerelease === null) return -1;
  // Lexicographic fallback — good enough for the D6 use case.
  return a.prerelease < b.prerelease ? -1 : a.prerelease > b.prerelease ? 1 : 0;
}

/**
 * `actual < fixMin` returns true iff actual is below the fixMin threshold.
 * Both strings must parse as semver; parse failures return false (we never
 * flag a version we cannot parse).
 */
export function isBelow(actual: string, fixMin: string): boolean {
  const a = parseVersion(actual);
  const b = parseVersion(fixMin);
  if (!a || !b) return false;
  return compareVersion(a, b) < 0;
}
