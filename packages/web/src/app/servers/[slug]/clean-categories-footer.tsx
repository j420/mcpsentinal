/**
 * CleanCategoriesFooter — single quiet row at the bottom of the page
 * listing categories with zero findings, in canonical taxonomy order.
 *
 * No severity colour. No collapse. One line, three columns: a small
 * checkmark, the category title, and the rules-tested count.
 */

import React from "react";
import type { CleanCategory } from "./view-model";

export interface CleanCategoriesFooterProps {
  categories: CleanCategory[];
}

export default function CleanCategoriesFooter({
  categories,
}: CleanCategoriesFooterProps): React.ReactElement | null {
  if (categories.length === 0) return null;
  return (
    <section
      className="fv-clean"
      aria-labelledby="fv-clean-h"
      id="clean-categories"
    >
      <h2 id="fv-clean-h" className="fv-clean-h">
        Tested cleanly
      </h2>
      <ul className="fv-clean-list">
        {categories.map((c) => (
          <li key={c.id} className="fv-clean-row">
            <span className="fv-clean-check" aria-hidden="true">
              ✓
            </span>
            <span className="fv-clean-title">{c.title}</span>
            <span className="fv-clean-count">
              {c.rulesTotal} rule{c.rulesTotal === 1 ? "" : "s"} tested cleanly
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
