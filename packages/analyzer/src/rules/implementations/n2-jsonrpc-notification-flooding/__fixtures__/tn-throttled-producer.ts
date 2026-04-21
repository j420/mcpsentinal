/**
 * True negative — notification wrapped in a throttle primitive. The rule
 * must recognise throttle vocabulary in the enclosing function and suppress
 * the finding.
 */

declare function throttle<T extends (...a: any[]) => void>(fn: T, ms: number): T;
declare const emit: (e: unknown, data: unknown) => void;

export function registerUpdater(data: unknown): void {
  const throttledNotify = throttle((payload: unknown) => emit("update", payload), 1000);
  setInterval(() => throttledNotify(data), 100);
}
