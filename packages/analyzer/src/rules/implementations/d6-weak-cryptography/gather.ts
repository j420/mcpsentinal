/**
 * D6 evidence gathering — exact-name blocklist + semver gate on installed
 * version.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { WEAK_CRYPTO_PACKAGES, type WeakCryptoSpec } from "./data/weak-crypto-packages.js";
import { isBelow } from "./data/semver.js";
import { inferEcosystem, jsonPointerForDep } from "../_shared/dependency-location.js";

export interface WeakCryptoSite {
  dependencyLocation: Location;
  configLocation: Location;
  name: string;
  version: string;
  ecosystem: "npm" | "pypi" | "go" | "rubygems" | "cargo";
  spec: WeakCryptoSpec;
  /** True when the safe_min_version threshold is what drove the finding. */
  firedBySemverGate: boolean;
}

export interface D6Gathered {
  sites: WeakCryptoSite[];
}

export function gatherD6(context: AnalysisContext): D6Gathered {
  const sites: WeakCryptoSite[] = [];

  for (const dep of context.dependencies) {
    if (!dep.name) continue;
    const spec = WEAK_CRYPTO_PACKAGES[dep.name];
    if (!spec) continue;

    const version = dep.version ?? "unknown";

    if (spec.safe_min_version === null) {
      // No safe version — always fire.
      sites.push(makeSite(dep.name, version, spec, false));
      continue;
    }

    // Version-gated entry: only fire if installed < safe_min_version.
    if (dep.version && isBelow(dep.version, spec.safe_min_version)) {
      sites.push(makeSite(dep.name, version, spec, true));
    }
  }

  return { sites };
}

function makeSite(
  name: string,
  version: string,
  spec: WeakCryptoSpec,
  firedBySemverGate: boolean,
): WeakCryptoSite {
  const ecosystem = inferEcosystem(name);
  return {
    dependencyLocation: {
      kind: "dependency",
      ecosystem,
      name,
      version,
    },
    configLocation: {
      kind: "config",
      file: ecosystem === "npm" ? "package.json" : "pyproject.toml",
      json_pointer: jsonPointerForDep(ecosystem, name),
    },
    name,
    version,
    ecosystem,
    spec,
    firedBySemverGate,
  };
}
