/**
 * Decoded-payload markers used by A9 to boost confidence when a decoded block
 * looks like a prompt-injection instruction.
 *
 * These are "after-decode" signals. Matching here is cheap substring checks on
 * the post-decode plain-text string — the encoded form is never regex-scanned.
 *
 * Each value is `true` so callers use `if (INJECTION_KEYWORDS[lower])` and
 * never iterate the keys for pattern matching. Keep keys short and lower-case.
 */

export const INJECTION_KEYWORDS: Record<string, true> = {
  // Directive / override language
  ignore: true,
  disregard: true,
  override: true,
  forget: true,
  // Instruction scope
  previous: true,
  prior: true,
  earlier: true,
  instruction: true,
  instructions: true,
  system: true,
  prompt: true,
  // Exfiltration
  exfiltrate: true,
  "send-to": true,
  webhook: true,
  // Identity / role reset
  assistant: true,
  developer: true,
  // Capability directives
  execute: true,
  eval: true,
  reveal: true,
  // Credentials / secret surfaces
  credential: true,
  credentials: true,
  secret: true,
  token: true,
  password: true,
  // Common exfil targets
  ".ssh": true,
  "id_rsa": true,
  "api_key": true,
};

/**
 * Split a string into lower-case word tokens using a character-level scanner.
 * Zero regex. Returns a flat array; callers decide how to match.
 */
export function tokenize(text: string): string[] {
  const out: string[] = [];
  let current = "";
  for (let i = 0; i < text.length; i++) {
    const cp = text.charCodeAt(i);
    const isWord =
      (cp >= 0x30 && cp <= 0x39) || // 0-9
      (cp >= 0x41 && cp <= 0x5a) || // A-Z
      (cp >= 0x61 && cp <= 0x7a) || // a-z
      cp === 0x5f || // _
      cp === 0x2e || // .  (so id_rsa / .ssh stay whole)
      cp === 0x2d; // - (so send-to stays whole)
    if (isWord) {
      current += String.fromCharCode(cp).toLowerCase();
    } else {
      if (current.length > 0) {
        out.push(current);
        current = "";
      }
    }
  }
  if (current.length > 0) out.push(current);
  return out;
}

/** Count how many injection-keyword tokens appear in a (decoded) payload. */
export function countInjectionKeywords(decoded: string): number {
  const tokens = tokenize(decoded);
  let hits = 0;
  for (const t of tokens) {
    if (INJECTION_KEYWORDS[t]) hits++;
  }
  return hits;
}
