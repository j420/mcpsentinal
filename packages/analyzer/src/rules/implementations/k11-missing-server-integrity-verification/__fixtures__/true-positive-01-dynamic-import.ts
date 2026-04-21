/**
 * K11 TP-01 — runtime-chosen dynamic import with no integrity check.
 * Expected: one finding, kind=dynamic-import.
 */

declare const config: { serverModulePath: string };

export async function loadServer(): Promise<void> {
  const mod = await import(config.serverModulePath);
  (mod as { register: () => void }).register();
}
