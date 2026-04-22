/**
 * O10 — Telemetry-Surface Vocabulary.
 *
 * Each Record holds ≤5 entries; the gather step iterates Records'
 * keys against AST Identifier / PropertyAccess texts. Zero regex.
 */

/**
 * OS / runtime surface identifiers. A call to any of these reads
 * host identity beyond the server's stated functionality.
 */
export const OS_SURFACE: Readonly<Record<string, string>> = {
  hostname: "os.hostname — machine hostname / FQDN",
  arch: "os.arch / process.arch — CPU architecture",
  platform: "os.platform / process.platform — OS family",
  release: "os.release — kernel release string",
  userInfo: "os.userInfo — local user account detail",
};

/**
 * Network interface / hardware identifier primitives.
 */
export const NETWORK_SURFACE: Readonly<Record<string, string>> = {
  networkInterfaces: "os.networkInterfaces — NICs (MAC + IP)",
  getifaddrs: "getifaddrs — POSIX interface addresses",
  ifaddresses: "netifaces.ifaddresses — Python interface addrs",
  mac: ".mac on a NIC entry — MAC address read",
  address: ".address on a NIC entry — IP read",
};

/**
 * Installed-software / dependency-version surfaces. Enumerating
 * these reveals the target's CVE-attack surface.
 */
export const SOFTWARE_SURFACE: Readonly<Record<string, string>> = {
  versions: "process.versions — runtime component versions",
  dependencies: "package.json dependencies enumeration",
  devDependencies: "package.json devDependencies enumeration",
  working_set: "pkg_resources.working_set — installed pkgs",
  pip: "pip freeze / pip list helpers",
};

/**
 * Device-identifier primitives. Persistent, non-rotatable box
 * identity.
 */
export const DEVICE_SURFACE: Readonly<Record<string, string>> = {
  "machine-id": "/etc/machine-id file",
  hwid: "hwid — generic hardware ID helper",
  MachineGuid: "Windows Registry MachineGuid",
  IOPlatformUUID: "macOS IOPlatformUUID",
  fingerprint: "fingerprintjs / @fingerprintjs/* helpers",
};

/**
 * Network-send primitives a gather step cross-references against
 * a telemetry-surface read in the same enclosing function.
 */
export const NETWORK_SEND_PRIMITIVES: Readonly<Record<string, string>> = {
  fetch: "global fetch / node-fetch",
  axios: "axios HTTP client",
  request: "http.request / http.post / requests.post",
  send: "WebSocket.send / socket.send",
  postMessage: "window.postMessage / MessagePort.postMessage",
};

/**
 * Consent / opt-in identifier vocabulary. If the enclosing
 * function's predicate reads one of these, the finding is
 * demoted (still emitted, lower confidence).
 */
export const CONSENT_IDENTIFIERS: Readonly<Record<string, string>> = {
  telemetryEnabled: "explicit telemetry toggle",
  consent: "user consent flag",
  optIn: "opt-in flag",
  allowTelemetry: "allow-telemetry capability",
  gdprConsent: "GDPR consent record",
};

/**
 * Pixel / analytics URL surface — indicator of tracking pixel
 * pattern in an HTML / markdown response.
 */
export const PIXEL_HINTS: Readonly<Record<string, string>> = {
  analytics: "generic analytics endpoint fragment",
  "google-analytics": "Google Analytics host",
  segment: "Segment analytics host",
  mixpanel: "Mixpanel host fragment",
  beacon: "navigator.sendBeacon / beacon pixel",
};
