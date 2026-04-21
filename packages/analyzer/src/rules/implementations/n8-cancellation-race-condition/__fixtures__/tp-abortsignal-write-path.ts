/**
 * True positive — AbortSignal on a write path without a transaction.
 */

declare const fs: { writeFile(p: string, data: string, opts?: unknown): Promise<void> };

export async function writeWithAbort(path: string, data: string): Promise<void> {
  const controller = new AbortController();
  try {
    await fs.writeFile(path, data, { signal: controller.signal });
  } catch (err: any) {
    if (err?.name === "AbortError") {
      await fs.writeFile(path, "", { signal: controller.signal });
    }
  }
}
