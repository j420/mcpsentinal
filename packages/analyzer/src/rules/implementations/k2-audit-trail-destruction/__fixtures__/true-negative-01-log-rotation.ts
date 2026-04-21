// true-negative-01: legitimate log rotation with archive + compress.
// The unlink is still flagged (rotation without retention is a
// violation), but severity drops to "high" (not critical) because
// a rotation marker is present in the enclosing scope. In practice a
// strict audit would ALSO require append-only storage — but at
// source-file scope this is the best-case shape.
//
// Rotation marker (`archive`, `compress`, `gzip`) in the enclosing
// function + unlink = severity "high", not "critical".

import * as fs from "fs";
import { gzipSync } from "zlib";

async function rotateAndCompress(logPath: string) {
  const contents = fs.readFileSync(logPath);
  // archive step: compress before delete
  fs.writeFileSync(`${logPath}.archive.gz`, gzipSync(contents));
  fs.unlinkSync(logPath);
}

rotateAndCompress("/var/log/app.log");
