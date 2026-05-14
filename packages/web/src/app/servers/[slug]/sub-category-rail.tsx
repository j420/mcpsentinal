/**
 * SubCategoryRail — even quieter typographic divider than CategoryRail.
 *
 * h3 + finding count, indented. No dot, no chips, no permalink hash
 * (the category rail above carries the permalink for navigation).
 */

import React from "react";

export interface SubCategoryRailProps {
  id: string;
  title: string;
  findingCount: number;
}

function subCategoryAnchor(id: string): string {
  return `sub-${id}`;
}

export default function SubCategoryRail({
  id,
  title,
  findingCount,
}: SubCategoryRailProps): React.ReactElement {
  return (
    <header className="fv-sub-rail" id={subCategoryAnchor(id)}>
      <h3 className="fv-sub-title">{title}</h3>
      <span className="fv-sub-count">
        {findingCount} finding{findingCount === 1 ? "" : "s"}
      </span>
    </header>
  );
}
