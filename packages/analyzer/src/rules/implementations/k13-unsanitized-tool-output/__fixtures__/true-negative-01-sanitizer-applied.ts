/**
 * K13 TN-01 — fetch → sanitize → return. Sanitizer is applied to the
 * returned identifier (`safe`), so the finding is suppressed.
 */

import DOMPurify from "dompurify";

export async function safeScrape(url: string): Promise<string> {
  const page = await fetch(url);
  const html = await page.text();
  const safe = DOMPurify.sanitize(html);
  return safe;
}
