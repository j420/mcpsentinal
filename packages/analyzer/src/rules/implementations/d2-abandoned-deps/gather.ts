/**
 * D2 evidence gathering — enumerate dependencies whose last_updated is
 * farther back than the abandonment threshold.
 *
 * Deterministic time arithmetic only. No registry fetches, no heuristics
 * beyond the publish-date comparison.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { inferEcosystem, jsonPointerForDep } from "../_shared/dependency-location.js";

const MS_PER_DAY = 24 * 60 * 60 * 1000;
export const ABANDONMENT_THRESHOLD_DAYS = 365;
export const HIGH_RISK_AGE_MONTHS = 36;

export interface AbandonedSite {
  dependencyLocation: Location;
  configLocation: Location;
  name: string;
  version: string;
  ecosystem: "npm" | "pypi" | "go" | "rubygems" | "cargo";
  lastUpdated: string;
  ageDays: number;
  ageMonths: number;
  /** True if age is past the high-risk boundary (charter's graduated factor). */
  isHighRisk: boolean;
}

export interface D2Gathered {
  sites: AbandonedSite[];
}

/**
 * Compute the site list. `now` defaults to Date.now() but is a parameter
 * to make tests deterministic.
 */
export function gatherD2(
  context: AnalysisContext,
  now: number = Date.now(),
): D2Gathered {
  const sites: AbandonedSite[] = [];

  for (const dep of context.dependencies) {
    // Null last_updated is a coverage gap, NOT a finding.
    if (!dep.last_updated) continue;

    const lastUpdated = coerceToDate(dep.last_updated);
    if (!lastUpdated) continue;

    const ageDays = Math.floor((now - lastUpdated.getTime()) / MS_PER_DAY);
    if (ageDays <= ABANDONMENT_THRESHOLD_DAYS) continue;

    const ageMonths = Math.floor(ageDays / 30);
    const version = dep.version ?? "unknown";
    const ecosystem = inferEcosystem(dep.name);

    sites.push({
      dependencyLocation: {
        kind: "dependency",
        ecosystem,
        name: dep.name,
        version,
      },
      configLocation: {
        kind: "config",
        file: ecosystem === "npm" ? "package.json" : "pyproject.toml",
        json_pointer: jsonPointerForDep(ecosystem, dep.name),
      },
      name: dep.name,
      version,
      ecosystem,
      lastUpdated: lastUpdated.toISOString(),
      ageDays,
      ageMonths,
      isHighRisk: ageMonths >= HIGH_RISK_AGE_MONTHS,
    });
  }

  return { sites };
}

/**
 * The engine declares `last_updated: Date | null` but older TypedRules were
 * written against a string. Accept either form without introducing regex.
 */
function coerceToDate(value: unknown): Date | null {
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null;
  if (typeof value === "string") {
    const d = new Date(value);
    return Number.isFinite(d.getTime()) ? d : null;
  }
  if (typeof value === "number") {
    const d = new Date(value);
    return Number.isFinite(d.getTime()) ? d : null;
  }
  return null;
}
