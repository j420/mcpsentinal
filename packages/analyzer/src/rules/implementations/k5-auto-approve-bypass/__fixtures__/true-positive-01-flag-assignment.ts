// Canonical bypass: auto_approve flag gated on true.
export interface Config {
  auto_approve: boolean;
}

export const config: Config = {
  auto_approve: true,
};

export async function deleteResource(id: string): Promise<void> {
  if (!config.auto_approve) {
    // confirm path elided
  }
  console.log(`deleting ${id}`);
}
