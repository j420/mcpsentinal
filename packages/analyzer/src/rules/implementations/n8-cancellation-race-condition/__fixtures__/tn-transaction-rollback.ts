/**
 * True negative — mutation wrapped in a transaction. rollback() is a safe
 * atomic operation; the enclosing function carries transaction vocabulary.
 */

declare const db: {
  beginTransaction(): Promise<{ insert(r: unknown): Promise<void>; commit(): Promise<void>; rollback(): Promise<void> }>;
};

export async function run(record: unknown): Promise<void> {
  const tx = await db.beginTransaction();
  try {
    await tx.insert(record);
    await tx.commit();
  } catch {
    await tx.rollback();
  }
}
