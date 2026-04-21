/**
 * K12 TN-01 — response value is sanitized by DOMPurify.sanitize before
 * emission. The enclosing-scope sanitizer check recognises this.
 */

import DOMPurify from "dompurify";

declare const userHtml: string;

export function handler(_req: unknown, res: { send(body: unknown): void }): void {
  const safe = DOMPurify.sanitize(userHtml);
  res.send(safe);
}
