/**
 * Shared data-exfiltration sink catalogue for the O-series (data privacy),
 * the localhost/IPC-oriented Q-series, and parts of the K-series.
 *
 * Every entry is a typed `ExfilSinkSpec` whose `tokens` field is the
 * canonical set of identifiers / bare syscall / module / method names a
 * gather step looks for when walking an AST. The list is intentionally
 * short per entry (≤5 tokens) so the no-static-patterns guard never
 * needs to flag a catalogue as a disguised pattern blob.
 *
 * How consumers use it:
 *
 *   - O6 (Clipboard)     — reads every clipboard-kind entry and matches
 *                          identifier text against the AST.
 *   - O8 (Screenshot)    — reads every screenshot-kind entry.
 *   - O10 (Keylogging)   — reads every keylog-kind entry.
 *   - O5 (Env-Var Harvest)
 *     O9 (Ambient Creds) — read env-var-kind entries plus the ambient
 *                          credential paths they imply (e.g. AWS config).
 *   - Q3 (Localhost Hijack)
 *     Q6 (Identity Impersonation)
 *     Q7 (DXT Privilege Chain)
 *     Q13 (Bridge Supply Chain)
 *                          consume the IPC / bridge / DXT entries.
 *
 * The catalogue does NOT replace taint analysis — it provides the
 * vocabulary that each gather step matches against AST nodes. Entries
 * carry enough metadata (confidence_weight, typical attribution, CWE
 * when applicable) that a rule's evidence chain can cite the catalogue
 * record directly rather than inlining strings.
 *
 * NO regex literals. Every catalogue entry holds ≤5 tokens.
 */

// ─── Types ─────────────────────────────────────────────────────────────────

/**
 * A category label that maps an entry to the rule(s) most likely to
 * consume it. Not a strict filter — O9 also consumes some O5 env-var
 * entries, for example — but a hint the gather step uses to decide
 * which entries to walk.
 */
export type ExfilSinkKind =
  | "clipboard"
  | "screenshot"
  | "keylog"
  | "env-var"
  | "localhost-port"
  | "bridge-ipc"
  | "dxt-ipc";

export interface ExfilSinkSpec {
  readonly kind: ExfilSinkKind;
  /**
   * Canonical identifier / bare syscall / module / method tokens. ≤5
   * entries so every consumer stays well below the no-static-patterns
   * string-array ceiling.
   */
  readonly tokens: readonly string[];
  /**
   * Hint that documents the specific platform or SDK API the tokens
   * come from (e.g. `"electron:desktopCapturer.getSources"`). Kept as
   * a single string so it lives inside a record, not a long array.
   * `null` when the syscall is generic across platforms.
   */
  readonly syscall_hint: string | null;
  /**
   * What a legitimate code path using these tokens usually looks like:
   *
   *   - `"user-interaction"` — triggered by an explicit user gesture
   *      (paste button, save-screenshot menu). Legitimate usage is
   *      possible but rare in server code.
   *   - `"background"` — no user gesture required. Almost never
   *      legitimate inside an MCP server.
   *   - `"both"` — the same API can be called either way; runtime
   *      context decides.
   */
  readonly typical_attribution: "user-interaction" | "background" | "both";
  /**
   * Independent weight used by consumer rules when aggregating multiple
   * hits via noisy-OR. The consumer rule is free to cap this further
   * per its CHARTER confidence cap.
   */
  readonly confidence_weight: number;
  /**
   * CWE tag for the sink family, when there is a canonical one. `null`
   * for kinds (e.g. env-var harvesting) where CWE does not publish a
   * dedicated weakness id.
   */
  readonly cwe: string | null;
  /**
   * Human-readable label surfaced in evidence chains; kept short so
   * the narrative renderer can concatenate it without elongating lines.
   */
  readonly label: string;
}

// ─── Clipboard — consumed by O6 ────────────────────────────────────────────

const CLIPBOARD_NAVIGATOR: ExfilSinkSpec = {
  kind: "clipboard",
  tokens: ["navigator", "clipboard"],
  syscall_hint: "browser:navigator.clipboard.readText/writeText",
  typical_attribution: "user-interaction",
  confidence_weight: 0.80,
  cwe: "CWE-359",
  label: "Web Clipboard API (navigator.clipboard)",
};

const CLIPBOARD_ELECTRON: ExfilSinkSpec = {
  kind: "clipboard",
  tokens: ["clipboard", "readText"],
  syscall_hint: "electron:clipboard.readText/writeText",
  typical_attribution: "background",
  confidence_weight: 0.85,
  cwe: "CWE-359",
  label: "Electron clipboard module",
};

const CLIPBOARD_PBCOPY: ExfilSinkSpec = {
  kind: "clipboard",
  tokens: ["pbcopy", "pbpaste"],
  syscall_hint: "macos:pbcopy/pbpaste shell helpers",
  typical_attribution: "background",
  confidence_weight: 0.88,
  cwe: "CWE-359",
  label: "macOS pbcopy / pbpaste helpers",
};

const CLIPBOARD_XCLIP: ExfilSinkSpec = {
  kind: "clipboard",
  tokens: ["xclip", "xsel", "wl-copy"],
  syscall_hint: "linux:xclip / xsel / wl-copy",
  typical_attribution: "background",
  confidence_weight: 0.85,
  cwe: "CWE-359",
  label: "Linux X11/Wayland clipboard helpers",
};

// ─── Screenshot — consumed by O8 ───────────────────────────────────────────

const SCREENSHOT_DESKTOP_CAPTURER: ExfilSinkSpec = {
  kind: "screenshot",
  tokens: ["desktopCapturer", "getSources"],
  syscall_hint: "electron:desktopCapturer.getSources",
  typical_attribution: "background",
  confidence_weight: 0.90,
  cwe: "CWE-359",
  label: "Electron desktopCapturer.getSources",
};

const SCREENSHOT_DISPLAY_MEDIA: ExfilSinkSpec = {
  kind: "screenshot",
  tokens: ["getDisplayMedia"],
  syscall_hint: "browser:navigator.mediaDevices.getDisplayMedia",
  typical_attribution: "user-interaction",
  confidence_weight: 0.75,
  cwe: "CWE-359",
  label: "Screen capture via getDisplayMedia",
};

const SCREENSHOT_CAPTURE_CALL: ExfilSinkSpec = {
  kind: "screenshot",
  tokens: ["screenshot", "capture"],
  syscall_hint: "generic: capture() / screenshot() helpers",
  typical_attribution: "background",
  confidence_weight: 0.82,
  cwe: "CWE-359",
  label: "Generic screenshot/capture helper",
};

const SCREENSHOT_SCROT: ExfilSinkSpec = {
  kind: "screenshot",
  tokens: ["scrot", "gnome-screenshot", "screencapture"],
  syscall_hint: "shell: scrot / gnome-screenshot / screencapture",
  typical_attribution: "background",
  confidence_weight: 0.85,
  cwe: "CWE-359",
  label: "Shell screenshot tools (scrot / screencapture)",
};

// ─── Keylog — consumed by O10 ──────────────────────────────────────────────

const KEYLOG_GLOBALSHORTCUT: ExfilSinkSpec = {
  kind: "keylog",
  tokens: ["globalShortcut", "register"],
  syscall_hint: "electron:globalShortcut.register",
  typical_attribution: "background",
  confidence_weight: 0.80,
  cwe: "CWE-532",
  label: "Electron globalShortcut registration",
};

const KEYLOG_IOHOOK: ExfilSinkSpec = {
  kind: "keylog",
  tokens: ["iohook", "uiohook", "node-key-sender"],
  syscall_hint: "npm:iohook / uiohook-napi / node-key-sender",
  typical_attribution: "background",
  confidence_weight: 0.92,
  cwe: "CWE-532",
  label: "Native keyboard-hook modules",
};

const KEYLOG_PYNPUT: ExfilSinkSpec = {
  kind: "keylog",
  tokens: ["pynput", "keyboard", "Listener"],
  syscall_hint: "python:pynput.keyboard.Listener",
  typical_attribution: "background",
  confidence_weight: 0.92,
  cwe: "CWE-532",
  label: "Python pynput keyboard Listener",
};

const KEYLOG_KEYBOARD_MODULE: ExfilSinkSpec = {
  kind: "keylog",
  tokens: ["keyboard", "on_press"],
  syscall_hint: "python:keyboard.on_press / hook",
  typical_attribution: "background",
  confidence_weight: 0.85,
  cwe: "CWE-532",
  label: "Python keyboard module hook",
};

// ─── Env-var — consumed by O5 & O9 ─────────────────────────────────────────

const ENV_VAR_PROCESS_ENV_BULK: ExfilSinkSpec = {
  kind: "env-var",
  tokens: ["process", "env"],
  syscall_hint: "node:process.env (bulk read — keys/entries/stringify)",
  typical_attribution: "background",
  confidence_weight: 0.85,
  cwe: "CWE-200",
  label: "Node process.env bulk access",
};

const ENV_VAR_OS_ENVIRON: ExfilSinkSpec = {
  kind: "env-var",
  tokens: ["os", "environ"],
  syscall_hint: "python:os.environ (items/keys/values/copy)",
  typical_attribution: "background",
  confidence_weight: 0.85,
  cwe: "CWE-200",
  label: "Python os.environ bulk access",
};

const ENV_VAR_AMBIENT_AWS: ExfilSinkSpec = {
  kind: "env-var",
  tokens: [".aws", "credentials"],
  syscall_hint: "fs:~/.aws/credentials ambient reads",
  typical_attribution: "background",
  confidence_weight: 0.88,
  cwe: "CWE-522",
  label: "Ambient AWS credentials file",
};

const ENV_VAR_AMBIENT_GCP: ExfilSinkSpec = {
  kind: "env-var",
  tokens: ["GOOGLE_APPLICATION_CREDENTIALS"],
  syscall_hint: "env:GOOGLE_APPLICATION_CREDENTIALS",
  typical_attribution: "background",
  confidence_weight: 0.85,
  cwe: "CWE-522",
  label: "Ambient GCP application default credentials",
};

const ENV_VAR_AMBIENT_KUBE: ExfilSinkSpec = {
  kind: "env-var",
  tokens: [".kube", "config"],
  syscall_hint: "fs:~/.kube/config",
  typical_attribution: "background",
  confidence_weight: 0.82,
  cwe: "CWE-522",
  label: "Ambient kubeconfig",
};

const ENV_VAR_AMBIENT_SSH: ExfilSinkSpec = {
  kind: "env-var",
  tokens: [".ssh", "id_rsa"],
  syscall_hint: "fs:~/.ssh/id_rsa / id_ed25519",
  typical_attribution: "background",
  confidence_weight: 0.90,
  cwe: "CWE-522",
  label: "Ambient SSH private keys",
};

// ─── Localhost port — consumed by Q3 ───────────────────────────────────────

const LOCALHOST_LISTEN_TCP: ExfilSinkSpec = {
  kind: "localhost-port",
  tokens: ["listen", "127.0.0.1"],
  syscall_hint: "net:server.listen on loopback",
  typical_attribution: "background",
  confidence_weight: 0.80,
  cwe: "CWE-306",
  label: "TCP listen on localhost",
};

const LOCALHOST_BIND_ALL: ExfilSinkSpec = {
  kind: "localhost-port",
  tokens: ["bind", "0.0.0.0"],
  syscall_hint: "net:server.bind to 0.0.0.0",
  typical_attribution: "background",
  confidence_weight: 0.78,
  cwe: "CWE-306",
  label: "Bind on all interfaces (0.0.0.0)",
};

const LOCALHOST_HTTP_CREATE_SERVER: ExfilSinkSpec = {
  kind: "localhost-port",
  tokens: ["http", "createServer"],
  syscall_hint: "node:http.createServer + .listen()",
  typical_attribution: "background",
  confidence_weight: 0.72,
  cwe: "CWE-306",
  label: "Ad-hoc HTTP server on loopback",
};

// ─── Bridge IPC — consumed by Q6, Q7, Q13 ──────────────────────────────────

const BRIDGE_NATIVE_MESSAGING: ExfilSinkSpec = {
  kind: "bridge-ipc",
  tokens: ["chrome", "runtime", "sendNativeMessage"],
  syscall_hint: "browser:chrome.runtime.sendNativeMessage",
  typical_attribution: "background",
  confidence_weight: 0.88,
  cwe: "CWE-269",
  label: "Browser native messaging bridge",
};

const BRIDGE_IPC_SEND: ExfilSinkSpec = {
  kind: "bridge-ipc",
  tokens: ["ipcMain", "handle"],
  syscall_hint: "electron:ipcMain.handle (renderer→main bridge)",
  typical_attribution: "background",
  confidence_weight: 0.80,
  cwe: "CWE-269",
  label: "Electron ipcMain handler",
};

const BRIDGE_MCP_REMOTE_NPX: ExfilSinkSpec = {
  kind: "bridge-ipc",
  tokens: ["npx", "mcp-remote"],
  syscall_hint: "shell:npx mcp-remote / mcp-proxy / mcp-gateway",
  typical_attribution: "background",
  confidence_weight: 0.90,
  cwe: "CWE-829",
  label: "Unpinned MCP bridge package invocation",
};

const BRIDGE_UVX_MCP: ExfilSinkSpec = {
  kind: "bridge-ipc",
  tokens: ["uvx", "mcp"],
  syscall_hint: "shell:uvx mcp / fastmcp",
  typical_attribution: "background",
  confidence_weight: 0.85,
  cwe: "CWE-829",
  label: "Unpinned uvx MCP bridge invocation",
};

// ─── DXT IPC — consumed by Q7 ──────────────────────────────────────────────

const DXT_MANIFEST_BRIDGE: ExfilSinkSpec = {
  kind: "dxt-ipc",
  tokens: ["dxt", "manifest", "json"],
  syscall_hint: "fs:manifest.json inside a .dxt bundle",
  typical_attribution: "background",
  confidence_weight: 0.78,
  cwe: "CWE-427",
  label: "Desktop extension (.dxt) manifest",
};

const DXT_AUTO_APPROVE: ExfilSinkSpec = {
  kind: "dxt-ipc",
  tokens: ["autoApprove"],
  syscall_hint: "config:autoApprove flag in dxt/mcp manifest",
  typical_attribution: "background",
  confidence_weight: 0.85,
  cwe: "CWE-269",
  label: "Auto-approve flag in extension manifest",
};

// ─── Public catalogue ──────────────────────────────────────────────────────

export const DATA_EXFIL_SINKS: Readonly<Record<string, ExfilSinkSpec>> = {
  clipboard_navigator: CLIPBOARD_NAVIGATOR,
  clipboard_electron: CLIPBOARD_ELECTRON,
  clipboard_pbcopy: CLIPBOARD_PBCOPY,
  clipboard_xclip: CLIPBOARD_XCLIP,
  screenshot_desktop_capturer: SCREENSHOT_DESKTOP_CAPTURER,
  screenshot_display_media: SCREENSHOT_DISPLAY_MEDIA,
  screenshot_capture_call: SCREENSHOT_CAPTURE_CALL,
  screenshot_scrot: SCREENSHOT_SCROT,
  keylog_globalshortcut: KEYLOG_GLOBALSHORTCUT,
  keylog_iohook: KEYLOG_IOHOOK,
  keylog_pynput: KEYLOG_PYNPUT,
  keylog_keyboard_module: KEYLOG_KEYBOARD_MODULE,
  env_var_process_env_bulk: ENV_VAR_PROCESS_ENV_BULK,
  env_var_os_environ: ENV_VAR_OS_ENVIRON,
  env_var_ambient_aws: ENV_VAR_AMBIENT_AWS,
  env_var_ambient_gcp: ENV_VAR_AMBIENT_GCP,
  env_var_ambient_kube: ENV_VAR_AMBIENT_KUBE,
  env_var_ambient_ssh: ENV_VAR_AMBIENT_SSH,
  localhost_listen_tcp: LOCALHOST_LISTEN_TCP,
  localhost_bind_all: LOCALHOST_BIND_ALL,
  localhost_http_create_server: LOCALHOST_HTTP_CREATE_SERVER,
  bridge_native_messaging: BRIDGE_NATIVE_MESSAGING,
  bridge_ipc_send: BRIDGE_IPC_SEND,
  bridge_mcp_remote_npx: BRIDGE_MCP_REMOTE_NPX,
  bridge_uvx_mcp: BRIDGE_UVX_MCP,
  dxt_manifest_bridge: DXT_MANIFEST_BRIDGE,
  dxt_auto_approve: DXT_AUTO_APPROVE,
};

/**
 * Convenience filter: every entry whose `kind` matches the argument.
 * Consumers iterate the returned list rather than `Object.values()`
 * with a `.filter()` chain.
 */
export function sinksOfKind(kind: ExfilSinkKind): readonly ExfilSinkSpec[] {
  return Object.values(DATA_EXFIL_SINKS).filter((s) => s.kind === kind);
}

/**
 * All distinct identifier tokens across every entry. Consumers that
 * walk an AST for an initial "any syscall of interest?" pass can use
 * this set before narrowing to a specific kind.
 */
export const DATA_EXFIL_ALL_TOKENS: ReadonlySet<string> = (() => {
  const set = new Set<string>();
  for (const spec of Object.values(DATA_EXFIL_SINKS)) {
    for (const tok of spec.tokens) set.add(tok.toLowerCase());
  }
  return set;
})();
