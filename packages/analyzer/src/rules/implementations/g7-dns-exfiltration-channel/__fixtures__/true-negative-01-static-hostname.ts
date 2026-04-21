// true-negative-01: static hardcoded hostname. Must NOT fire.

import * as dns from "dns";

function healthcheck() {
  dns.resolve("api.example.com", "A", () => {});
  dns.lookup("localhost", () => {});
}

healthcheck();
