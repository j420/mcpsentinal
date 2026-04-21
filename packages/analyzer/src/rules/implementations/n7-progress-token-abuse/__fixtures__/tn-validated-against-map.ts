/**
 * True negative — crypto generator produces the token (even if a user input
 * is present elsewhere, the crypto call in the scope inverts the finding
 * per CHARTER.md "absence-of-crypto-generator" mitigation requirement).
 */

import * as crypto from "node:crypto";

export class Server {
  validateProgressToken(_t: string): boolean { return true; }

  accept(_req: { body: { progressId: string } }): string {
    const progressToken = crypto.randomUUID();
    if (!this.validateProgressToken(progressToken)) throw new Error("invalid");
    return progressToken;
  }
}
