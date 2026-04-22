/**
 * D5 evidence gathering — exact-match blocklist lookup with Unicode
 * normalisation pass.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { normalizeConfusables } from "../../analyzers/unicode.js";
import {
  KNOWN_MALICIOUS_PACKAGES,
  type MaliciousPackageSpec,
} from "./data/malicious-packages.js";
import { inferEcosystem, jsonPointerForDep } from "../_shared/dependency-location.js";

export interface MaliciousPackageSite {
  dependencyLocation: Location;
  configLocation: Location;
  name: string;
  /** The NAME used for the blocklist hit — may equal name, or be a
   * Unicode-normalised form of name. */
  matchedName: string;
  version: string;
  ecosystem: "npm" | "pypi" | "go" | "rubygems" | "cargo";
  spec: MaliciousPackageSpec;
  /** True if the hit was found after Unicode normalisation (homoglyph attack). */
  viaUnicodeNormalisation: boolean;
}

export interface D5Gathered {
  sites: MaliciousPackageSite[];
}

export function gatherD5(context: AnalysisContext): D5Gathered {
  const sites: MaliciousPackageSite[] = [];

  for (const dep of context.dependencies) {
    if (!dep.name) continue;

    // 1. Exact match — the primary path.
    const exactSpec = KNOWN_MALICIOUS_PACKAGES[dep.name];
    if (exactSpec) {
      sites.push(makeSite(dep.name, dep.name, dep.version, exactSpec, false));
      continue;
    }

    // 2. Unicode-normalised match — catches Cyrillic-homoglyph attacks.
    const normalised = normalizeConfusables(dep.name);
    if (normalised !== dep.name) {
      const normSpec = KNOWN_MALICIOUS_PACKAGES[normalised];
      if (normSpec) {
        sites.push(makeSite(dep.name, normalised, dep.version, normSpec, true));
        continue;
      }
    }
  }

  return { sites };
}

function makeSite(
  candidate: string,
  matchedName: string,
  version: string | null,
  spec: MaliciousPackageSpec,
  viaUnicodeNormalisation: boolean,
): MaliciousPackageSite {
  const ecosystem = spec.ecosystem === "pypi" ? "pypi" : inferEcosystem(candidate);
  const v = version ?? "unknown";
  return {
    dependencyLocation: {
      kind: "dependency",
      ecosystem,
      name: candidate,
      version: v,
    },
    configLocation: {
      kind: "config",
      file: ecosystem === "npm" ? "package.json" : "pyproject.toml",
      json_pointer: jsonPointerForDep(ecosystem, candidate),
    },
    name: candidate,
    matchedName,
    version: v,
    ecosystem,
    spec,
    viaUnicodeNormalisation,
  };
}
