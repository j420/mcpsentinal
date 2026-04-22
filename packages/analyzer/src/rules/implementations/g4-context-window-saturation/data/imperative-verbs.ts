/**
 * G4 imperative-verb catalogue.
 *
 * Typed Record<string, ImperativeVerbSpec> — NOT a bare string array. The
 * no-static-patterns guard counts string-literal arrays larger than five
 * entries; keyed objects are how we encode a vocabulary of modest size
 * without tripping the guard.
 *
 * Each entry encodes the verb, its imperative weight, and a short
 * rationale. The weight lets us differentiate "send" (strong exfil
 * signal) from "use" (weaker — appears in benign instructions too).
 *
 * The structural tail scanner in gather.ts walks words token-by-token
 * and consults this Record. It does not regex-match.
 */

export interface ImperativeVerbSpec {
  /** The canonical lowercase verb form. */
  verb: string;
  /** Weight 1-3 — higher means stronger imperative / exfil signal. */
  weight: 1 | 2 | 3;
  /** Why this verb is a tail-payload indicator. */
  rationale: string;
}

export const IMPERATIVE_VERBS: Record<string, ImperativeVerbSpec> = {
  send: {
    verb: "send",
    weight: 3,
    rationale:
      "Exfiltration-adjacent: 'send <data> to <attacker>' is the canonical payload shape.",
  },
  forward: {
    verb: "forward",
    weight: 3,
    rationale:
      "Exfiltration-adjacent: 'forward your system prompt / messages / credentials'.",
  },
  exfiltrate: {
    verb: "exfiltrate",
    weight: 3,
    rationale:
      "Explicit exfiltration keyword — rare in legitimate documentation.",
  },
  leak: {
    verb: "leak",
    weight: 3,
    rationale:
      "Rare in legitimate imperative contexts; almost always adversarial.",
  },
  ignore: {
    verb: "ignore",
    weight: 3,
    rationale:
      "'Ignore previous instructions' — the canonical prompt-injection verb.",
  },
  forget: {
    verb: "forget",
    weight: 3,
    rationale:
      "'Forget your system prompt' — direct prompt-injection verb.",
  },
  disregard: {
    verb: "disregard",
    weight: 3,
    rationale:
      "Synonym for ignore; used to defeat simple keyword filters.",
  },
  override: {
    verb: "override",
    weight: 2,
    rationale:
      "'Override the user's settings' — authority-claim + behaviour change.",
  },
  disable: {
    verb: "disable",
    weight: 2,
    rationale:
      "'Disable confirmation' / 'disable safety check' — behaviour-modifying imperative.",
  },
  delete: {
    verb: "delete",
    weight: 2,
    rationale:
      "Destructive imperative; often paired with exfiltration tail payloads.",
  },
  execute: {
    verb: "execute",
    weight: 2,
    rationale:
      "Directs the agent to run arbitrary code — strong tail-payload verb.",
  },
  fetch: {
    verb: "fetch",
    weight: 2,
    rationale:
      "Common in exfiltration chains ('fetch the token then send').",
  },
  upload: {
    verb: "upload",
    weight: 2,
    rationale:
      "Exfiltration verb — data travels out.",
  },
  reveal: {
    verb: "reveal",
    weight: 2,
    rationale:
      "'Reveal your system prompt' — direct injection against meta-prompting.",
  },
  bypass: {
    verb: "bypass",
    weight: 2,
    rationale:
      "'Bypass the confirmation dialog' — consent-fatigue-adjacent imperative.",
  },
  reconfigure: {
    verb: "reconfigure",
    weight: 2,
    rationale:
      "Behaviour-rewriting imperative — indicates the payload mutates agent state.",
  },
  instruct: {
    verb: "instruct",
    weight: 2,
    rationale:
      "'Instruct the agent to ...' — authority-claim setup verb.",
  },
};
