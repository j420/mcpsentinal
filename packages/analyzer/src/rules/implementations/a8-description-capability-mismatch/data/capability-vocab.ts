/**
 * A8 — typed catalogue of read-only claim phrases and destructive
 * parameter-name tokens. No regex.
 */

export interface ClaimPhrase {
  tokens: readonly string[];
  weight: number;
  label: string;
  max_gap: number;
}

/** Catalogue of "read-only / safe / non-destructive" claim phrases. */
export const READ_ONLY_CLAIMS: readonly ClaimPhrase[] = [
  { tokens: ["read", "only"], weight: 0.85, label: "read-only claim", max_gap: 1 },
  { tokens: ["readonly"], weight: 0.85, label: "readonly claim", max_gap: 0 },
  { tokens: ["just", "reads"], weight: 0.80, label: "just-reads claim", max_gap: 1 },
  { tokens: ["only", "reads"], weight: 0.80, label: "only-reads claim", max_gap: 1 },
  { tokens: ["safe"], weight: 0.60, label: "safe claim", max_gap: 0 },
  { tokens: ["non", "destructive"], weight: 0.85, label: "non-destructive claim", max_gap: 1 },
  { tokens: ["nondestructive"], weight: 0.85, label: "nondestructive claim", max_gap: 0 },
  { tokens: ["no", "side", "effects"], weight: 0.85, label: "no-side-effects claim", max_gap: 1 },
];

/** Write-capable parameter name tokens. */
export const WRITE_PARAM_TOKENS: ReadonlySet<string> = new Set([
  "delete", "remove", "write", "create", "update",
  "modify", "overwrite", "drop", "truncate", "kill",
  "terminate", "execute", "run", "send", "post",
  "put", "patch", "destroy", "erase", "reset",
]);

/** Network-send parameter name tokens. */
export const NETWORK_PARAM_TOKENS: ReadonlySet<string> = new Set([
  "webhook", "webhook_url", "callback", "endpoint", "url",
  "notify", "notify_url",
]);

/** Dangerous default values keyed by param-name token. */
export interface DangerousDefault {
  value_tokens: readonly string[];
  label: string;
}

export const DANGEROUS_DEFAULTS: Readonly<Record<string, DangerousDefault>> = {
  overwrite: { value_tokens: ["true"], label: "overwrite: true" },
  recursive: { value_tokens: ["true"], label: "recursive: true" },
  force: { value_tokens: ["true"], label: "force: true" },
  delete: { value_tokens: ["true"], label: "delete: true" },
};
