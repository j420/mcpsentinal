"use client";
/**
 * ForensicTrigger — opens the slide-over Forensic drawer for a specific
 * finding by writing `?finding=<id>` to the URL.
 *
 * The button lives at the bottom of every finding panel inside
 * `<RuleEvidenceCard/>`. Clicking it appends the finding id to the URL;
 * the drawer (mounted once at the page root) reads `useSearchParams()`
 * and renders accordingly. URL state means a sharable link reaches the
 * same drawer state and browser back/forward works.
 *
 * Tiny client component — single hook + single onClick handler. No
 * state of its own; the URL is the source of truth.
 */

import React, { useCallback } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

interface ForensicTriggerProps {
  findingId: string;
}

export default function ForensicTrigger({ findingId }: ForensicTriggerProps) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const onClick = useCallback(() => {
    const params = new URLSearchParams(searchParams.toString());
    params.set("finding", findingId);
    router.replace(`${pathname}?${params.toString()}`, { scroll: false });
  }, [router, pathname, searchParams, findingId]);

  return (
    <button
      type="button"
      className="rec-finding-forensic"
      onClick={onClick}
      aria-label="Open forensic view for this finding"
      title="Open the forensic audit pack for this finding"
    >
      <span aria-hidden="true">🗂</span>
      Open forensic view
    </button>
  );
}
