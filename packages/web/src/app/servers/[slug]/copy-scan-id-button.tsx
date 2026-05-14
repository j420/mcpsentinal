"use client";

/**
 * CopyScanIdButton — the only client island in the sticky header.
 *
 * Keeps HeaderRail server-rendered. Clipboard write is the only reason
 * we need a client component here. State is a 1.4s "copied!" flash.
 */

import React, { useCallback, useState } from "react";

export interface CopyScanIdButtonProps {
  /** Full scan id, written to clipboard. */
  fullScanId: string;
  /** Short display label, e.g. "a1b2c3d4". */
  shortLabel: string;
}

export default function CopyScanIdButton({
  fullScanId,
  shortLabel,
}: CopyScanIdButtonProps): React.ReactElement {
  const [copied, setCopied] = useState(false);

  const onCopy = useCallback(() => {
    if (typeof navigator === "undefined" || !navigator.clipboard) return;
    navigator.clipboard
      .writeText(fullScanId)
      .then(() => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1400);
      })
      .catch(() => {
        // Clipboard write blocked (older browser, no HTTPS, no perms).
        // Quietly do nothing — the id is still readable in the chip.
      });
  }, [fullScanId]);

  return (
    <button
      type="button"
      className="fv-hdr-scan"
      onClick={onCopy}
      title={`Scan ${fullScanId} — click to copy`}
      aria-label={`Copy scan id ${fullScanId}`}
    >
      <span className="fv-hdr-scan-eyebrow">Scan</span>
      <code className="fv-hdr-scan-id">{shortLabel}</code>
      <span className="fv-hdr-scan-copy" aria-hidden="true">
        {copied ? "✓" : "⧉"}
      </span>
    </button>
  );
}
