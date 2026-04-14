"use client";

/**
 * ServerTabs — Client-side tab group for the server detail page.
 *
 * Renders N tabs with `useState`-managed active panel. Content for each
 * tab is passed in as ReactNode via the `tabs` prop — Next.js serializes
 * server-component children across the RSC boundary so the existing
 * server-rendered Findings / Tools / Deep-Dive sections can be passed
 * directly alongside the client-component ComplianceTab.
 *
 * Accessibility: uses `role="tablist"` / `role="tab"` / `role="tabpanel"`
 * with `aria-selected` and `aria-controls` so screen readers announce the
 * tabs correctly. Inactive panels use `hidden` so they're removed from
 * the accessibility tree and skipped by keyboard focus.
 */

import React, { useState, type ReactNode } from "react";

export interface ServerTab {
  id: string;
  label: string;
  count?: number;
  content: ReactNode;
}

interface Props {
  tabs: ServerTab[];
  initialTabId?: string;
}

export default function ServerTabs({ tabs, initialTabId }: Props) {
  const firstId = tabs[0]?.id ?? "";
  const [active, setActive] = useState<string>(initialTabId ?? firstId);

  if (tabs.length === 0) return null;

  return (
    <div className="sd-tabs">
      <div
        role="tablist"
        aria-label="Server detail sections"
        className="sd-tabs-list"
      >
        {tabs.map((tab) => {
          const isActive = tab.id === active;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              id={`sd-tab-${tab.id}`}
              aria-selected={isActive}
              aria-controls={`sd-panel-${tab.id}`}
              tabIndex={isActive ? 0 : -1}
              className={`sd-tab${isActive ? " sd-tab-active" : ""}`}
              onClick={() => setActive(tab.id)}
            >
              <span className="sd-tab-label">{tab.label}</span>
              {typeof tab.count === "number" && (
                <span className="sd-tab-count">{tab.count}</span>
              )}
            </button>
          );
        })}
      </div>

      {tabs.map((tab) => {
        const isActive = tab.id === active;
        return (
          <div
            key={tab.id}
            role="tabpanel"
            id={`sd-panel-${tab.id}`}
            aria-labelledby={`sd-tab-${tab.id}`}
            hidden={!isActive}
            className="sd-tab-panel"
          >
            {tab.content}
          </div>
        );
      })}
    </div>
  );
}
