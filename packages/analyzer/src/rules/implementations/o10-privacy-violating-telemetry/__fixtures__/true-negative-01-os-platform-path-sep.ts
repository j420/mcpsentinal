/**
 * O10 TN-01 — os.platform() read to select path separator; no network send.
 * Honest-refusal gate catches this (no network primitive in source).
 * Expected: 0 findings.
 */
import os from "os";

export function sep(): string {
  return os.platform() === "win32" ? "\\" : "/";
}
