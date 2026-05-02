"use client";
/**
 * SectionBoundary — per-section React error boundary for the Deep Dive.
 *
 * One render exception in any section (verdict bar, hero, reel,
 * capability surface, coverage ledger, taxonomy, provenance, etc.) used
 * to take down the whole page via the route-level error.tsx. With this
 * wrapper, a failing section degrades to a small skeleton — the rest of
 * the page keeps working.
 *
 * Why class-based: React Suspense / `error.tsx` are route-level. To
 * catch a SINGLE component's render error without the whole route
 * blowing up, we still need a class-based boundary (React 19 has no
 * ergonomic functional API for this yet).
 *
 * The hidden DOM hint (`<span data-section-error>`) carries the section
 * name + error message so an operator can `View Source` on the live
 * page and see which section failed without server logs. The visible
 * fallback is a low-key dotted card so the layout stays balanced.
 */

import React from "react";

interface SectionBoundaryProps {
  /** Stable identifier surfaced in the digest hint and in the hidden
   *  data attribute. Use "kebab-case-section-name". */
  section: string;
  /** Optional human-readable label rendered in the visible fallback. */
  label?: string;
  children: React.ReactNode;
}

interface SectionBoundaryState {
  error: Error | null;
}

export default class SectionBoundary extends React.Component<
  SectionBoundaryProps,
  SectionBoundaryState
> {
  state: SectionBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): SectionBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo): void {
    // eslint-disable-next-line no-console
    console.error(
      `[SectionBoundary:${this.props.section}] render failed:`,
      error,
      info,
    );
  }

  render(): React.ReactNode {
    if (this.state.error) {
      const label = this.props.label ?? this.props.section;
      const msg = this.state.error.message ?? String(this.state.error);
      return (
        <aside
          className="section-boundary-fallback"
          data-section-error={this.props.section}
          data-section-error-msg={msg}
          aria-label={`${label} failed to render`}
        >
          <span className="section-boundary-glyph" aria-hidden="true">
            ⚠
          </span>
          <span className="section-boundary-text">
            <strong>{label}</strong> could not render — the rest of the
            page is unaffected.
          </span>
          {process.env.NODE_ENV !== "production" && (
            <code className="section-boundary-msg">{msg}</code>
          )}
        </aside>
      );
    }
    return this.props.children;
  }
}
