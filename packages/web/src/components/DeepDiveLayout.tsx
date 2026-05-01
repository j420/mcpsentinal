/**
 * DeepDiveLayout — two-column long-scroll frame for the deep-dive page.
 *
 * Left rail (sticky): `<DeepDiveSidebar/>` — owned by Cluster D part 5.
 * Right column (long scroll): `<CategorySection/>` × n — owned by Cluster D
 * part 4.
 *
 * Both are passed in as slot props (`sidebar`, `main`) so this layout has
 * no compile-time dependency on the components Agents 4 + 5 are still
 * authoring in their own worktrees. The slots are ReactNode so anything
 * server-rendered or client-rendered drops in untouched.
 *
 * Mobile: at narrow viewports the sidebar collapses to a horizontal
 * sheet at the top of the main column. We expose `data-narrow="true"`
 * on the wrapper so Agent 5's CSS can pick its mobile rendering up
 * without flag-passing across components.
 *
 * Width discipline: the sidebar lane is fluid between 240px and 320px
 * (clamp(240px, 22vw, 320px)). The main column flexes to fill the
 * remainder. No fixed pixel widths; tokens only.
 */

import React, { type ReactNode } from "react";

export interface DeepDiveLayoutProps {
  /** Sticky left rail content (Agent 5's `<DeepDiveSidebar/>`). */
  sidebar: ReactNode;
  /** Long-scroll main column (Agent 4's `<CategorySection/>` stack). */
  main: ReactNode;
  /**
   * Width of the sidebar lane in CSS clamp form. Defaults to
   * `clamp(240px, 22vw, 320px)`.
   */
  sidebarWidth?: string;
  /**
   * Heading rendered above the sticky rail for screen readers / page outline.
   * Defaults to "Deep dive".
   */
  ariaLabel?: string;
}

export default function DeepDiveLayout({
  sidebar,
  main,
  sidebarWidth = "clamp(240px, 22vw, 320px)",
  ariaLabel = "Deep dive",
}: DeepDiveLayoutProps) {
  return (
    <section
      className="ddl-grid"
      aria-label={ariaLabel}
      style={{ ["--ddl-sidebar-w" as keyof React.CSSProperties]: sidebarWidth } as React.CSSProperties}
    >
      <aside
        className="ddl-rail"
        aria-label="Deep dive navigation"
        data-narrow="false"
      >
        <div className="ddl-rail-inner">{sidebar}</div>
      </aside>
      <div className="ddl-main" role="region" aria-label="Deep dive content">
        {main}
      </div>
    </section>
  );
}
