/**
 * A2 scope-claim vocabulary. Pairs of modifier + noun that together form
 * excessive-scope claims when co-located within a small token window.
 * No regex — the gatherer walks the token stream and checks co-occurrence.
 */

export interface ClaimSpec {
  modifier_tokens: readonly string[]; // ANY of these counts as the modifier
  noun_tokens: readonly string[]; // ANY of these is the scope noun
  weight: number;
  label: string;
  /** Max tokens between modifier and noun for the claim to count. */
  max_gap: number;
}

/** Modifier-type groups — each noun group pairs with all modifiers. */
const UNRESTRICTED_MODIFIERS: readonly string[] = [
  "full", "complete", "unrestricted", "unlimited", "unfettered",
];

const BROAD_MODIFIERS: readonly string[] = [
  "all", "any", "every", "entire",
];

const ACCESS_NOUNS: readonly string[] = [
  "access", "control", "permission", "privilege", "permissions",
];

const DATA_NOUNS: readonly string[] = [
  "files", "data", "records", "resources",
];

const ELEVATED_ROLE_NOUNS: readonly string[] = [
  "admin", "administrator", "root", "superuser", "god",
];

const ELEVATED_ROLE_MODE_NOUNS: readonly string[] = [
  "mode", "privilege", "access", "role",
];

const READ_WRITE_VERBS: readonly string[] = [
  "read", "write", "modify", "delete",
];

export const CLAIM_SPECS: readonly ClaimSpec[] = [
  {
    modifier_tokens: UNRESTRICTED_MODIFIERS,
    noun_tokens: ACCESS_NOUNS,
    weight: 0.85,
    label: "unrestricted-access",
    max_gap: 2,
  },
  {
    modifier_tokens: BROAD_MODIFIERS,
    noun_tokens: DATA_NOUNS,
    weight: 0.75,
    label: "all-data-scope",
    max_gap: 2,
  },
  {
    modifier_tokens: ELEVATED_ROLE_NOUNS,
    noun_tokens: ELEVATED_ROLE_MODE_NOUNS,
    weight: 0.85,
    label: "elevated-role-claim",
    max_gap: 1,
  },
  {
    modifier_tokens: READ_WRITE_VERBS,
    noun_tokens: BROAD_MODIFIERS,
    weight: 0.80,
    label: "read-write-any",
    max_gap: 1,
  },
];
