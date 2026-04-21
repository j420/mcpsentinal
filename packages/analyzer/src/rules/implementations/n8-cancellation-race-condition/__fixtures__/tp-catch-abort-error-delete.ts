/**
 * True positive — cleanup-in-catch-without-state-check: catch (AbortError)
 * branch deletes without confirming the original write actually failed.
 */

declare const db: {
  insert(r: unknown): Promise<{ id: string }>;
  delete(id: string): Promise<void>;
};

export async function run(record: unknown): Promise<void> {
  let inserted: { id: string } | null = null;
  try {
    inserted = await db.insert(record);
  } catch (err: any) {
    if (err?.name === "AbortError" && inserted) {
      await db.delete(inserted.id);
    }
  }
}
