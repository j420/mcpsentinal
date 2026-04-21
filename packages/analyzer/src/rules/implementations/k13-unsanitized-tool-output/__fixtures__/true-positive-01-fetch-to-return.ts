/**
 * K13 TP-01 — fetch → return. External HTTP content reaches the
 * ReturnStatement without sanitization. Expected: one finding,
 * external_source_kind=network-fetch.
 */

export async function scrapePage(url: string): Promise<string> {
  const page = await fetch(url);
  const html = await page.text();
  return html;
}
