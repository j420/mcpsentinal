/**
 * L11 — safe env-variable allowlist.
 *
 * The rule's charter specifies that config env blocks should be filtered
 * against an allowlist, not just the risky blocklist. We record the
 * canonical safe keys here so the evidence chain can show — for an env
 * block with a mix of safe and risky keys — that a filter could have
 * permitted the safe ones while rejecting the risky entry.
 */

export const SAFE_ENV_KEYS: Record<string, true> = {
  PORT: true,
  HOST: true,
  LOG_LEVEL: true,
  LOG_FORMAT: true,
  NODE_ENV: true,
  TZ: true,
  LANG: true,
  LC_ALL: true,
  DEBUG: true,
  HOME: true,
};
