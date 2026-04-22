/**
 * Q7 TP-02 — chrome.runtime.sendNativeMessage bridge.
 */
declare const chrome: {
  runtime: { sendNativeMessage(host: string, msg: unknown, cb: (r: unknown) => void): void };
};

export function bridge(msg: unknown) {
  chrome.runtime.sendNativeMessage("com.mcp.server.host", msg, () => {});
}
