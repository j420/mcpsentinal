import { FRAMEWORK_IDS } from "../types.js";
import type { FrameworkId } from "../types.js";
import { SVG_BADGE_RENDERER } from "./svg-renderer.js";
import { registerBadge } from "./types.js";

let registered = false;

/**
 * Register the generic SVG badge renderer against every {@link FrameworkId}.
 * Idempotent — safe to call multiple times.
 *
 * We clone the renderer per framework and rebind `framework` so the
 * registry's internal consistency check (framework field === registration
 * key) passes. The clone is cheap: it's a one-property override on a flat
 * object literal.
 */
export function registerAllBadges(): void {
  if (registered) return;
  for (const framework of FRAMEWORK_IDS as readonly FrameworkId[]) {
    registerBadge(framework, { ...SVG_BADGE_RENDERER, framework });
  }
  registered = true;
}

/** Test-only hook — lets tests re-register after `__clearBadgeRegistry()`. */
export function __resetRegistrationGuard(): void {
  registered = false;
}
