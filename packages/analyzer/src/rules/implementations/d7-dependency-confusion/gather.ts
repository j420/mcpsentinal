/**
 * D7 evidence gathering — scoped packages with suspiciously high major
 * version numbers.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  KNOWN_PRIVATE_NAMESPACE_PREFIXES,
  type KnownPrivateNamespace,
} from "./data/known-private-scopes.js";
import { parseVersion } from "../d6-weak-cryptography/data/semver.js";
import { jsonPointerForDep } from "../_shared/dependency-location.js";

export const SUSPICIOUS_MAJOR_THRESHOLD = 99;
export const HIGHLY_SUSPICIOUS_MAJOR_THRESHOLD = 999;

export interface ConfusionSite {
  dependencyLocation: Location;
  configLocation: Location;
  name: string;
  version: string;
  major: number;
  isHighlySuspicious: boolean;
  /** Scope prefix like "@acme" — always non-null because we only consider scoped packages. */
  scope: string;
  /** Known-private-namespace record when the scope matches a curated entry. */
  knownPrivateMatch: KnownPrivateNamespace | null;
}

export interface D7Gathered {
  sites: ConfusionSite[];
}

export function gatherD7(context: AnalysisContext): D7Gathered {
  const sites: ConfusionSite[] = [];

  for (const dep of context.dependencies) {
    if (!dep.name) continue;
    if (!dep.version) continue;

    // Scoped packages only — D7's attack surface is the Birsan technique.
    if (dep.name.charCodeAt(0) !== 0x40 /* @ */) continue;

    const parsed = parseVersion(dep.version);
    if (!parsed) continue;

    if (parsed.major < SUSPICIOUS_MAJOR_THRESHOLD) continue;

    const scope = extractScope(dep.name);
    if (!scope) continue;

    sites.push({
      dependencyLocation: {
        kind: "dependency",
        ecosystem: "npm",
        name: dep.name,
        version: dep.version,
      },
      configLocation: {
        kind: "config",
        file: "package.json",
        json_pointer: jsonPointerForDep("npm", dep.name),
      },
      name: dep.name,
      version: dep.version,
      major: parsed.major,
      isHighlySuspicious: parsed.major >= HIGHLY_SUSPICIOUS_MAJOR_THRESHOLD,
      scope,
      knownPrivateMatch: KNOWN_PRIVATE_NAMESPACE_PREFIXES[scope] ?? null,
    });
  }

  return { sites };
}

function extractScope(name: string): string | null {
  if (name.length === 0 || name.charCodeAt(0) !== 0x40 /* @ */) return null;
  const slash = name.indexOf("/");
  if (slash <= 1) return null;
  return name.slice(0, slash);
}
