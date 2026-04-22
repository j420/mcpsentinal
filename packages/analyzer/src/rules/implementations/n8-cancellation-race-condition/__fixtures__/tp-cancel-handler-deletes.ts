/**
 * True positive — named cancel handler that deletes partial results without
 * checking whether the operation already committed (cancel-after-commit).
 */

declare const db: { delete(id: string): Promise<void> };

export function handleCancel(operationId: string): Promise<void> {
  return db.delete(operationId);
}
