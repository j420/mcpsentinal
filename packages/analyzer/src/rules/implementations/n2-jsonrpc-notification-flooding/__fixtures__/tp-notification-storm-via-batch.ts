/**
 * True positive — "notification-storm-via-batch-reply" lethal edge case.
 * The producer loop is the outer for-of over batch entries, and each
 * iteration synchronously emits a progress notification.
 */

declare const sendNotification: (n: unknown) => void;

export function handleBatch(batch: unknown[]): void {
  for (const entry of batch) {
    sendNotification({ method: "notifications/progress", params: { entry } });
  }
}
