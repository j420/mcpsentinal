/**
 * H2 TP-04 — Unicode control character (U+202E RTL override) in
 * serverInfo.name.
 *
 * The RTL override codepoint is invisible to human review in most
 * terminals (it only reorders subsequent text). It is a classic
 * Unicode injection used to disguise trailing payloads. Detected via
 * analyzers/unicode.ts bidi_override issue kind.
 *
 * Covers CHARTER lethal edge case #4.
 */
import type { AnalysisContext } from "../../../../engine.js";

// Build the name at runtime so the raw control char never appears as
// a literal in source code.
const RTL_OVERRIDE = String.fromCodePoint(0x202e);
const NAME_WITH_RTL = `filesystem-${RTL_OVERRIDE}eciv-res`;

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "h2-tp04",
      name: NAME_WITH_RTL,
      description: null,
      github_url: null,
    },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
