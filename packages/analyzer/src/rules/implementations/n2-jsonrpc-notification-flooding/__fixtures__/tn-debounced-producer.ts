/**
 * True negative — debounced notification. Throttle vocabulary present.
 */

declare function debounce<T extends (...a: any[]) => void>(fn: T, ms: number): T;
declare const emit: (e: unknown) => void;

export function makeDebouncedNotifier(): () => void {
  return debounce(() => emit("update"), 500);
}
