/**
 * Q7 TN-02 — handle() on a non-ipcMain receiver (e.g. Express router).
 * Must NOT fire — receiver is not in IPC_RECEIVERS.
 */
declare const router: {
  handle(path: string, handler: (req: unknown, res: unknown) => void): void;
};

export function mount() {
  router.handle("/ping", (_req, res) => {
    void res;
  });
}
