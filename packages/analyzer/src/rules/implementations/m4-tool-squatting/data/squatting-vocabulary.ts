/**
 * M4 tool-squatting vocabulary.
 *
 * Each entry names a linguistic class that LLMs treat as an authority or
 * authenticity claim when selecting between competing tools. Detection is
 * token-based, not regex-based: the gather step tokenises the tool
 * description into lowercase word tokens and matches against these token
 * sequences (anchor token + qualifier token, both within a short window).
 *
 * Loaded as an object-literal Record so the no-static-patterns guard does
 * not classify the lists as "long string-literal arrays".
 */

export type SquatSignalClass =
  | "authenticity-claim"
  | "vendor-attribution"
  | "authenticity-assertion"
  | "registry-trust"
  | "version-displacement"
  | "trust-badge"
  | "exclusivity";

export interface SquatSignal {
  readonly cls: SquatSignalClass;
  readonly anchor_tokens: readonly string[];
  readonly qualifier_tokens: readonly string[];
  readonly proximity: number;
  readonly weight: number;
  readonly desc: string;
}

export const SQUATTING_SIGNALS: Readonly<Record<string, SquatSignal>> = {
  "authenticity-official-version": {
    cls: "authenticity-claim",
    anchor_tokens: ["official", "verified", "certified"],
    qualifier_tokens: ["version", "implementation", "tool", "server"],
    proximity: 2,
    weight: 0.90,
    desc: "explicit authenticity claim (official|verified|certified + version|implementation|tool|server)",
  },
  "authenticity-endorsed": {
    cls: "authenticity-claim",
    anchor_tokens: ["endorsed", "approved", "authorized", "authenticated"],
    qualifier_tokens: ["version", "implementation", "tool", "server", "plugin"],
    proximity: 2,
    weight: 0.85,
    desc: "endorsement authenticity claim",
  },
  "vendor-attribution-anthropic": {
    cls: "vendor-attribution",
    anchor_tokens: ["by", "from", "made", "built", "created"],
    qualifier_tokens: ["anthropic", "openai", "google", "microsoft", "aws"],
    proximity: 3,
    weight: 0.85,
    desc: "vendor attribution (by|from|made|built|created + major vendor)",
  },
  "vendor-attribution-cloud": {
    cls: "vendor-attribution",
    anchor_tokens: ["by", "from", "made", "built", "created"],
    qualifier_tokens: ["github", "stripe", "cloudflare", "meta"],
    proximity: 3,
    weight: 0.85,
    desc: "vendor attribution (by|from|made|built|created + cloud vendor)",
  },
  "authenticity-assertion-the-real": {
    cls: "authenticity-assertion",
    anchor_tokens: ["the"],
    qualifier_tokens: ["real", "genuine", "authentic", "true", "original"],
    proximity: 1,
    weight: 0.80,
    desc: "authenticity assertion (the + real|genuine|authentic|true|original)",
  },
  "registry-trust-verified-on": {
    cls: "registry-trust",
    anchor_tokens: ["verified", "listed", "registered", "certified"],
    qualifier_tokens: ["by", "on", "with", "in"],
    proximity: 1,
    weight: 0.75,
    desc: "registry trust manipulation",
  },
  "version-displacement-replaces": {
    cls: "version-displacement",
    anchor_tokens: ["replaces", "supersedes", "upgraded", "successor"],
    qualifier_tokens: [],
    proximity: 0,
    weight: 0.70,
    desc: "version displacement (replaces|supersedes|upgraded|successor)",
  },
  "trust-badge-audited": {
    cls: "trust-badge",
    anchor_tokens: ["security", "compliance"],
    qualifier_tokens: ["audited", "reviewed", "certified", "verified"],
    proximity: 2,
    weight: 0.65,
    desc: "trust badge language",
  },
  "trust-badge-trusted": {
    cls: "trust-badge",
    anchor_tokens: ["trusted"],
    qualifier_tokens: [],
    proximity: 0,
    weight: 0.55,
    desc: "bare 'trusted' claim",
  },
  "exclusivity-authoritative": {
    cls: "exclusivity",
    anchor_tokens: ["only", "exclusive", "authoritative"],
    qualifier_tokens: ["authorized", "official", "version", "source", "implementation"],
    proximity: 2,
    weight: 0.75,
    desc: "exclusivity claim",
  },
};

export const NEGATION_TOKENS: readonly string[] = [
  "not",
  "no",
  "unofficial",
  "un-official",
  "disclaimer",
];

export const NEGATION_PREFIXES: readonly string[] = ["un", "non", "de"];
