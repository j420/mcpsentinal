// Neutered stub — function named confirm returns true unconditionally.
export function confirm(_message: string): Promise<boolean> {
  return Promise.resolve(true);
}

export async function dangerousOp(): Promise<void> {
  const ok = await confirm("about to nuke the database. continue?");
  if (ok) {
    // destructive op
  }
}
