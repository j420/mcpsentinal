/**
 * Presentation-only helpers used by HTML and PDF renderers. All functions
 * are pure and deterministic — the same input always yields the same
 * output, with no dependency on wall-clock time, locale, or environment.
 */

/** HTML-escape plain text for safe insertion into text nodes and attributes. */
export function escapeHtml(input: string): string {
  let out = "";
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    switch (ch) {
      case "&":
        out += "&amp;";
        break;
      case "<":
        out += "&lt;";
        break;
      case ">":
        out += "&gt;";
        break;
      case '"':
        out += "&quot;";
        break;
      case "'":
        out += "&#39;";
        break;
      default:
        out += ch;
    }
  }
  return out;
}

/**
 * Wrap a long string (e.g. base64 signature) at `width` characters per
 * line. Deterministic: no regex, no locale.
 */
export function wrapFixedWidth(input: string, width: number): string[] {
  if (width <= 0) return [input];
  const lines: string[] = [];
  for (let i = 0; i < input.length; i += width) {
    lines.push(input.slice(i, i + width));
  }
  return lines.length > 0 ? lines : [""];
}

/**
 * Format an ISO 8601 timestamp as a human-friendly UTC string without
 * regex or locale-dependent APIs.
 * Input:  "2026-04-23T12:34:56.789Z"
 * Output: "2026-04-23 12:34:56 UTC"
 */
export function formatIsoUtc(iso: string): string {
  // Defensive pass-through if input isn't the expected shape.
  if (iso.length < 19 || iso[10] !== "T") return iso;
  const date = iso.slice(0, 10);
  const time = iso.slice(11, 19);
  return `${date} ${time} UTC`;
}

/** Format a ratio 0–1 as a whole-percent string, e.g. 0.72 → "72%". */
export function formatPercent(ratio: number): string {
  if (!Number.isFinite(ratio)) return "—";
  const clamped = Math.min(1, Math.max(0, ratio));
  return `${Math.round(clamped * 100)}%`;
}

/**
 * Truncate to `max` chars with a trailing ellipsis when overlong. Used
 * defensively; buildReport already caps evidence_summary at 200 chars.
 */
export function truncate(input: string, max: number): string {
  if (input.length <= max) return input;
  return input.slice(0, Math.max(0, max - 1)) + "…";
}

/**
 * Slug-escape an arbitrary control id for use as an HTML anchor. Keeps
 * only letters, digits, and hyphens; other characters become "_".
 */
export function anchorSlug(controlId: string): string {
  let out = "";
  for (let i = 0; i < controlId.length; i++) {
    const cp = controlId.charCodeAt(i);
    const isDigit = cp >= 48 && cp <= 57;
    const isUpper = cp >= 65 && cp <= 90;
    const isLower = cp >= 97 && cp <= 122;
    const isDash = cp === 45; // -
    if (isDigit || isUpper || isLower || isDash) {
      out += controlId[i];
    } else {
      out += "_";
    }
  }
  return `ctl-${out}`;
}
