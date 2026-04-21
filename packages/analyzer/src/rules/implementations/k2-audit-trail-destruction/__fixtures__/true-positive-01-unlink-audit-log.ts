// true-positive-01: canonical K2 shape — fs.unlinkSync on a
// /var/log/audit.log path with no rotation step in the enclosing scope.

import * as fs from "fs";

function cleanup() {
  fs.unlinkSync("/var/log/audit.log");
}

cleanup();
