/**
 * Generate shields.io-style SVG badges for MCP server security scores.
 *
 * Security notes:
 * - ALL user-derived strings (label, value) are XML-escaped before insertion.
 *   This prevents SVG/XML injection via crafted server names or scores.
 * - The aria-label and <title> attributes are escaped separately — they are
 *   distinct injection surfaces from the visible text nodes.
 * - Color is an internal constant, never derived from user input.
 */
export function createBadgeSvg(
  label: string,
  value: string,
  color: string
): string {
  const safeLabel = escapeXml(label);
  const safeValue = escapeXml(value);
  // color is always an internal hex constant — no escaping needed,
  // but validate it is a safe CSS color value to be defensive.
  const safeColor = /^#[0-9a-fA-F]{3,6}$/.test(color) ? color : "#999";

  const labelWidth = label.length * 7 + 12;
  const valueWidth = value.length * 7 + 12;
  const totalWidth = labelWidth + valueWidth;

  // aria-label and <title> use safeLabel/safeValue (XML-escaped).
  // Without this, a server named `"><script>` would inject into the SVG DOM
  // when the badge is embedded inline in an HTML page.
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${safeLabel}: ${safeValue}">
  <title>${safeLabel}: ${safeValue}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${safeColor}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="${labelWidth / 2}" y="14" fill="#010101" fill-opacity=".3">${safeLabel}</text>
    <text x="${labelWidth / 2}" y="13">${safeLabel}</text>
    <text x="${labelWidth + valueWidth / 2}" y="14" fill="#010101" fill-opacity=".3">${safeValue}</text>
    <text x="${labelWidth + valueWidth / 2}" y="13">${safeValue}</text>
  </g>
</svg>`;
}

/**
 * Escape characters that have special meaning in XML/SVG.
 * Applied to every user-derived string before insertion into SVG markup.
 */
function escapeXml(str: string): string {
  return str
    .replace(/&/g, "&amp;")   // must be first — prevents double-escaping
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");  // needed for attribute values using single quotes
}
