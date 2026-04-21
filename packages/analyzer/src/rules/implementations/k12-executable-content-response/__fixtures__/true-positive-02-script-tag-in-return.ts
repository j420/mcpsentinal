/**
 * K12 TP-02 — return statement carrying a <script> tag. Expected:
 * one finding, kind=script-tag-string.
 */

export function renderWelcome(): string {
  return `<div><script>alert('hi')</script></div>`;
}
