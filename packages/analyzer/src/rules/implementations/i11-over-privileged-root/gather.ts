/**
 * I11 gather — inspect context.roots against SENSITIVE_ROOT_PATHS
 * with per-entry fence tokens.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  SENSITIVE_ROOT_PATHS,
  type SensitiveRootSpec,
} from "../_shared/protocol-shape-catalogue.js";

export interface I11Fact {
  root_uri: string;
  root_name: string | null;
  match: SensitiveRootSpec;
  fence_hit: boolean;
}

export interface I11GatherResult {
  facts: I11Fact[];
}

export function gatherI11(context: AnalysisContext): I11GatherResult {
  const facts: I11Fact[] = [];
  const roots = context.roots;
  if (!roots || roots.length === 0) return { facts };

  for (const root of roots) {
    const uriLower = root.uri.toLowerCase();
    for (const spec of Object.values(SENSITIVE_ROOT_PATHS)) {
      const frag = spec.path_fragment.toLowerCase();
      if (!matchesFragment(uriLower, frag)) continue;
      const fenceHit = spec.false_positive_fence.some((token) =>
        uriLower.includes(token.toLowerCase()),
      );
      facts.push({
        root_uri: root.uri,
        root_name: root.name ?? null,
        match: spec,
        fence_hit: fenceHit,
      });
      break;
    }
  }
  return { facts };
}

function matchesFragment(uri: string, fragment: string): boolean {
  // Strip leading 'file://' if present for path comparison
  const path = uri.startsWith("file://") ? uri.substring(7) : uri;
  // Exact-root suffix match or equality (handles /etc, /etc/, /root, /root/).
  if (path === fragment) return true;
  if (path.endsWith(fragment)) return true;
  if (path.endsWith(`${fragment}/`)) return true;
  if (fragment === "file:///" && (path === "/" || path === "")) return true;
  if (uri === fragment) return true;
  // Directory inclusion: /etc matches /etc/something but only if the
  // fragment is a path prefix ending at a segment boundary.
  if (path.includes(fragment)) {
    // Ensure segment boundary — the fragment is followed by '/' or end-of-string.
    const idx = path.indexOf(fragment);
    const after = path.charAt(idx + fragment.length);
    if (after === "" || after === "/") return true;
  }
  return false;
}
