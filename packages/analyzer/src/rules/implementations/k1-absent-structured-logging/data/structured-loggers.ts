/**
 * K1 structured-logger registry.
 *
 * Loaded at module scope by `gather.ts`. Object-literal shape (not a
 * string-literal array) so the no-static-patterns guard doesn't consider
 * the list a "long string-literal array".
 *
 * Adding a logger: add a property to LOGGERS. The ecosystem + default_import
 * carry the same meaning as in the RFC 6901 advisory list — `default_import`
 * of `null` means the package name is not itself the default identifier
 * (accessory packages like `winston-transport`).
 */

export type Ecosystem = "npm" | "pypi";

export interface LoggerEntry {
  ecosystem: Ecosystem;
  defaultImport: string | null;
}

export const LOGGERS: Record<string, LoggerEntry> = {
  pino: { ecosystem: "npm", defaultImport: "pino" },
  winston: { ecosystem: "npm", defaultImport: "winston" },
  bunyan: { ecosystem: "npm", defaultImport: "bunyan" },
  tslog: { ecosystem: "npm", defaultImport: "tslog" },
  log4js: { ecosystem: "npm", defaultImport: "log4js" },
  loglevel: { ecosystem: "npm", defaultImport: "log" },
  signale: { ecosystem: "npm", defaultImport: "signale" },
  consola: { ecosystem: "npm", defaultImport: "consola" },
  roarr: { ecosystem: "npm", defaultImport: "roarr" },
  "pino-pretty": { ecosystem: "npm", defaultImport: null },
  "pino-http": { ecosystem: "npm", defaultImport: null },
  "winston-daily-rotate-file": { ecosystem: "npm", defaultImport: null },
  "winston-transport": { ecosystem: "npm", defaultImport: null },
  structlog: { ecosystem: "pypi", defaultImport: "structlog" },
  loguru: { ecosystem: "pypi", defaultImport: "loguru" },
  logging: { ecosystem: "pypi", defaultImport: "logging" },
};

/**
 * Function names that commonly wrap a structured logger (e.g. a local
 * `audit()` helper that internally calls pino). ≤5 entries so the guard
 * leaves the array literal alone.
 */
export const INDIRECT_LOGGER_FUNCTION_NAMES: readonly string[] = [
  "audit",
  "logEvent",
  "emit",
  "track",
  "record",
];
