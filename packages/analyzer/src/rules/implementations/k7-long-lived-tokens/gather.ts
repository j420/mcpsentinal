/**
 * K7 evidence gathering — tops off the AST walker in gather-ast.ts.
 *
 * Two categorical finding types:
 *   - TOKEN_CREATION findings: a library token-creation call with
 *     missing / excessive / disabled expiry.
 *   - EXPIRY_ASSIGNMENT findings: a bare property/binary assignment of
 *     an expiry-configuration property with a long duration or a disabling
 *     value. Useful for config-only files that don't themselves call
 *     jwt.sign — the library picks up the config at runtime.
 *
 * Zero regex. No string-literal arrays > 5.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { gatherFile } from "./gather-ast.js";

export type ExpiryFindingKind =
  | "no-expiry"
  | "excessive-expiry"
  | "disabled-expiry"
  | "excessive-expiry-refresh";

export interface TokenCreationSite {
  kind: "token-creation";
  location: Location; // kind: "source"
  callerLabel: string;            // "jwt.sign" / "jose.SignJWT" / "signToken"
  findingKind: ExpiryFindingKind;
  durationSeconds: number | null;
  observed: string;               // line text, trimmed, capped
  /** RFC 6901 path into the arguments object if the value came from a property. */
  durationJsonPointer: string | null;
  /** True when classifier infers this is a REFRESH token (looser threshold). */
  isRefreshToken: boolean;
}

export interface ExpiryAssignmentSite {
  kind: "expiry-assignment";
  location: Location; // kind: "source"
  propertyName: string;
  findingKind: ExpiryFindingKind;
  durationSeconds: number | null;
  observed: string;
  isRefreshToken: boolean;
}

export type K7Site = TokenCreationSite | ExpiryAssignmentSite;

export interface FileEvidence {
  file: string;
  sites: K7Site[];
  isTestFile: boolean;
}

export interface K7Gathered {
  perFile: FileEvidence[];
}

export function gatherK7(context: AnalysisContext): K7Gathered {
  const perFile: FileEvidence[] = [];
  const files = collectSourceFiles(context);
  for (const [file, text] of files) {
    perFile.push(gatherFile(file, text));
  }
  return { perFile };
}

function collectSourceFiles(context: AnalysisContext): Map<string, string> {
  const out = new Map<string, string>();
  if (context.source_files && context.source_files.size > 0) {
    for (const [k, v] of context.source_files) out.set(k, v);
    return out;
  }
  if (context.source_code) {
    out.set("<concatenated-source>", context.source_code);
  }
  return out;
}
