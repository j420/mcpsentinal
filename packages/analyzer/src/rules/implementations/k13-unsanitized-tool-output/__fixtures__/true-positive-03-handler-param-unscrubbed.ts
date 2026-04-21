/**
 * K13 TP-03 — handler parameter whose name implies external content is
 * returned directly. Expected: one finding, source kind=handler-param.
 */

export async function summarize(page: string): Promise<{ text: string }> {
  // `page` arrived from an upstream tool — trust-boundary crossing.
  return { text: page };
}
