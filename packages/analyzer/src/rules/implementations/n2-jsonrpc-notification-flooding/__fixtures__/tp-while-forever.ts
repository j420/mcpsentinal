/**
 * True positive — while-forever producer. No throttle, no break, no delay.
 */

declare const notify: (msg: unknown) => void;
declare const running: boolean;
declare const msg: unknown;

export function producer(): void {
  while (running) {
    notify(msg);
  }
}
