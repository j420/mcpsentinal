/**
 * True positive — setInterval-producer edge case. The loop is the interval.
 */

declare const push: (e: unknown) => void;
declare const events: unknown;

export function startHeartbeat(): void {
  setInterval(() => {
    push(events);
  }, 100);
}
