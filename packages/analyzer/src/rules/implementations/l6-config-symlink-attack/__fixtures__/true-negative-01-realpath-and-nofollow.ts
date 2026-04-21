// Both mitigations: realpath AND O_NOFOLLOW.
import fs from "node:fs";
import { constants } from "node:fs";

export function safeRead(userPath: string, rootDir: string): Buffer {
  const realPath = fs.realpathSync(userPath);
  if (!realPath.startsWith(rootDir)) {
    throw new Error("outside root");
  }
  const fd = fs.openSync(realPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const buf = Buffer.alloc(4096);
    fs.readSync(fd, buf, 0, buf.length, 0);
    return buf;
  } finally {
    fs.closeSync(fd);
  }
}
