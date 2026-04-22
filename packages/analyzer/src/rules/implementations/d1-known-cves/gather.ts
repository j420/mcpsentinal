/**
 * D1 evidence gathering — deterministic enumeration of dependencies
 * whose auditor output reports at least one known CVE.
 *
 * The gather step does NOT decide ecosystem heuristics or massage the
 * CVE list in any way. It faithfully reports the auditor data so the
 * evidence chain in index.ts cites exactly what the scanner's data
 * source asserted.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { inferEcosystem, jsonPointerForDep } from "../_shared/dependency-location.js";

/** A single vulnerable-dependency site the orchestrator turns into a finding. */
export interface KnownCveSite {
  /** Structured Location for the dependency entry itself. */
  dependencyLocation: Location; // kind: "dependency"
  /** Structured Location for the manifest entry. */
  configLocation: Location; // kind: "config"
  /** Package name. */
  name: string;
  /** Exact installed version (never null — entries with version=null are skipped). */
  version: string;
  /** Ecosystem inferred from name shape / manifest heuristics. */
  ecosystem: "npm" | "pypi" | "go" | "rubygems" | "cargo";
  /** All CVE ids reported by the auditor. */
  cveIds: string[];
  /** First CVE id — elevated to the chain's cve_precedent. */
  primaryCveId: string;
}

export interface D1Gathered {
  sites: KnownCveSite[];
}

export function gatherD1(context: AnalysisContext): D1Gathered {
  const sites: KnownCveSite[] = [];

  for (const dep of context.dependencies) {
    if (!dep.has_known_cve) continue;
    // Silent skip: empty cve_ids means the auditor flagged the package but
    // did not provide a concrete advisory id — the rule refuses to guess.
    if (!dep.cve_ids || dep.cve_ids.length === 0) continue;
    // Silent skip: null version (git url, github-url pin) — the evidence
    // chain must not claim a version string the manifest does not contain.
    if (!dep.version) continue;

    const ecosystem = inferEcosystem(dep.name);
    const dependencyLocation: Location = {
      kind: "dependency",
      ecosystem,
      name: dep.name,
      version: dep.version,
    };
    const configLocation: Location = {
      kind: "config",
      file: ecosystem === "npm" ? "package.json" : "pyproject.toml",
      json_pointer: jsonPointerForDep(ecosystem, dep.name),
    };

    sites.push({
      dependencyLocation,
      configLocation,
      name: dep.name,
      version: dep.version,
      ecosystem,
      cveIds: [...dep.cve_ids],
      primaryCveId: dep.cve_ids[0],
    });
  }

  return { sites };
}
