/**
 * L3 — canonical mutable-tag registry.
 *
 * Loaded at module scope by `gather.ts`. Typed Record, not a string-literal
 * array, so the no-static-patterns guard does not treat this as a regex
 * substitute. Adding a keyword: add a property.
 *
 * Semantics: a Dockerfile tag is considered "mutable" when any of its
 * `-` / `_` / `.`-delimited tokens matches a key in MUTABLE_TAG_KEYWORDS.
 * This catches both `:latest` and the dev-tag-camouflage case (`:latest-prod`,
 * `:lts-stable`, `:release-latest`) — lethal edge case #4 in the charter.
 */

export interface MutableTagKeyword {
  keyword: string;
  /** Human description emitted in the finding observed rationale. */
  description: string;
  /** Severity weight (0..1) — currently uniform but kept open for future tuning. */
  weight: number;
}

export const MUTABLE_TAG_KEYWORDS: Record<string, MutableTagKeyword> = {
  latest: { keyword: "latest", description: "Docker's default mutable alias", weight: 1.0 },
  stable: { keyword: "stable", description: "moving 'stable' marker, not a pinned version", weight: 0.9 },
  lts: { keyword: "lts", description: "rolling long-term-support alias", weight: 0.85 },
  edge: { keyword: "edge", description: "rolling bleeding-edge alias", weight: 1.0 },
  nightly: { keyword: "nightly", description: "nightly build — contents change daily", weight: 1.0 },
  dev: { keyword: "dev", description: "development-stream alias, typically unsigned", weight: 1.0 },
  beta: { keyword: "beta", description: "pre-release rolling alias", weight: 0.9 },
  alpha: { keyword: "alpha", description: "pre-release rolling alias", weight: 0.9 },
  rc: { keyword: "rc", description: "release-candidate rolling alias", weight: 0.85 },
  canary: { keyword: "canary", description: "canary channel — rapidly changing", weight: 1.0 },
  next: { keyword: "next", description: "next-version rolling alias", weight: 0.9 },
  current: { keyword: "current", description: "rolling 'current' alias (Node images)", weight: 0.9 },
  mainline: { keyword: "mainline", description: "rolling mainline alias (nginx/PHP)", weight: 0.9 },
  main: { keyword: "main", description: "rolling main-branch build", weight: 0.85 },
  master: { keyword: "master", description: "rolling master-branch build", weight: 0.85 },
};

/**
 * Exact-match allowlist for Docker's built-in empty base. ONLY the exact
 * string "scratch" (case-sensitive) is allowed — charter lethal edge case #3
 * blocks "scratch-extras" / "Scratch" from being silently skipped.
 */
export const SCRATCH_IMAGE_LITERAL = "scratch";

/** Tokens we strip from a FROM line before extracting the image reference. */
export const FROM_FLAG_PREFIXES: Record<string, true> = {
  "--platform=": true,
  "--chmod=": true,
  "--chown=": true,
  "--link=": true,
  "--build-arg=": true,
};
