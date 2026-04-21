/**
 * True negative — mutation guarded by a mutex. Lock vocabulary present.
 */

declare class Mutex { async acquire(): Promise<() => void> { return () => {}; } }

declare const fs: { writeFile(p: string, data: string): Promise<void> };

export async function writeWithLock(mutex: Mutex, path: string, data: string): Promise<void> {
  const release = await mutex.acquire();
  try {
    await fs.writeFile(path, data);
  } finally {
    release();
  }
}
