/**
 * Q7 TP-03 — ipcMain.handle wired to a tool flow.
 */
declare const ipcMain: {
  handle(channel: string, handler: (event: unknown, arg: unknown) => unknown): void;
};

export function register() {
  ipcMain.handle("tool-call", (_event, arg) => {
    void arg;
    return { ok: true };
  });
}
