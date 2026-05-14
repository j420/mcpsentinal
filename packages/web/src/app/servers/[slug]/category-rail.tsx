/**
 * CategoryRail — typographic divider, NOT a card.
 *
 * Categories are structural rails. Their job is to organise rule cards
 * into runs by attack vector, without competing visually with the rule
 * cards themselves. h2 + severity dot + finding count + hairline rule —
 * that is the whole component.
 */

import React from "react";
import type { DeepDiveSeverity } from "@/lib/deep-dive";

export interface CategoryRailProps {
  id: string;
  title: string;
  worstSeverity: DeepDiveSeverity;
  findingCount: number;
  frameworks?: string[];
}

function categoryAnchor(id: string): string {
  return `category-${id}`;
}

export default function CategoryRail({
  id,
  title,
  worstSeverity,
  findingCount,
  frameworks = [],
}: CategoryRailProps): React.ReactElement {
  return (
    <header className="fv-cat-rail" id={categoryAnchor(id)}>
      <span
        className="fv-cat-dot"
        data-severity={worstSeverity}
        aria-hidden="true"
      />
      <h2 className="fv-cat-title">{title}</h2>
      <span className="fv-cat-count">
        {findingCount} finding{findingCount === 1 ? "" : "s"}
      </span>
      {frameworks.length > 0 && (
        <span className="fv-cat-frameworks" aria-label="Compliance frameworks">
          {frameworks.map((f) => (
            <span key={f} className="fv-cat-fw">
              {f}
            </span>
          ))}
        </span>
      )}
      <a
        className="fv-cat-permalink"
        href={`#${categoryAnchor(id)}`}
        aria-label={`Permalink to ${title}`}
      >
        #
      </a>
    </header>
  );
}
