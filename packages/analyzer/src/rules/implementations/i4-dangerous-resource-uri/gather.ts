/**
 * I4 gather — scan each declared resource URI for dangerous schemes and
 * traversal markers. Uses the shared protocol-shape catalogue.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  DANGEROUS_URI_SCHEMES,
  TRAVERSAL_MARKERS,
  type UriSchemeSpec,
  type TraversalMarkerSpec,
} from "../_shared/protocol-shape-catalogue.js";

export interface I4Fact {
  resource_uri: string;
  resource_name: string;
  scheme_hit: UriSchemeSpec | null;
  traversal_hit: TraversalMarkerSpec | null;
  fence_hit: boolean;
}

export interface I4GatherResult {
  facts: I4Fact[];
}

export function gatherI4(context: AnalysisContext): I4GatherResult {
  const facts: I4Fact[] = [];
  const resources = context.resources;
  if (!resources || resources.length === 0) return { facts };

  for (const resource of resources) {
    const lower = resource.uri.toLowerCase();
    const schemeHit = findSchemeHit(lower);
    const traversalHit = findTraversalHit(lower);
    if (!schemeHit && !traversalHit) continue;

    const fenceHit = detectFence(lower, schemeHit, traversalHit);
    facts.push({
      resource_uri: resource.uri,
      resource_name: resource.name,
      scheme_hit: schemeHit,
      traversal_hit: traversalHit,
      fence_hit: fenceHit,
    });
  }
  return { facts };
}

function findSchemeHit(loweredUri: string): UriSchemeSpec | null {
  for (const spec of Object.values(DANGEROUS_URI_SCHEMES)) {
    if (loweredUri.startsWith(spec.scheme)) return spec;
  }
  return null;
}

function findTraversalHit(loweredUri: string): TraversalMarkerSpec | null {
  for (const spec of Object.values(TRAVERSAL_MARKERS)) {
    if (loweredUri.includes(spec.marker.toLowerCase())) return spec;
  }
  return null;
}

function detectFence(
  loweredUri: string,
  schemeHit: UriSchemeSpec | null,
  traversalHit: TraversalMarkerSpec | null,
): boolean {
  if (schemeHit) {
    for (const token of schemeHit.false_positive_fence) {
      if (loweredUri.includes(token)) return true;
    }
  }
  if (traversalHit) {
    // Traversal markers don't carry per-entry fences on this catalogue
    // record — the traversal itself is a strong signal regardless.
  }
  return false;
}
