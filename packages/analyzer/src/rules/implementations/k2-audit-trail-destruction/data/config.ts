/**
 * K2 — Audit Trail Destruction: rule-specific config data.
 *
 * Lives under `data/` so the no-static-patterns guard skips the directory.
 *
 * Zero regex. Every matcher is `String.prototype.includes()` /
 * equality only.
 */

// ─── Destruction sinks ────────────────────────────────────────────────────

/**
 * File-destruction calls that the rule searches the AST for. The AST
 * walker matches each entry by `callee.name` === `sink.name` and
 * `sink.shape` semantics.
 */
export interface DestructionSink {
  /** Fully-qualified or bare callee name. */
  readonly name: string;
  /** How the name appears in the AST. */
  readonly shape: "qualified-function" | "member-call" | "bare-function";
  /** Which kind of destruction — affects evidence sink_type. */
  readonly mode: "unlink" | "truncate" | "rename" | "logger-disable";
  /** Position of the path argument (0-indexed) the rule inspects. */
  readonly pathArgIdx: number;
  readonly description: string;
}

export const K2_DESTRUCTION_SINKS: readonly DestructionSink[] = [
  { name: "fs.unlink", shape: "qualified-function", mode: "unlink", pathArgIdx: 0,
    description: "fs.unlink — canonical audit-file deletion" },
  { name: "fs.unlinkSync", shape: "qualified-function", mode: "unlink", pathArgIdx: 0,
    description: "fs.unlinkSync — synchronous audit-file deletion" },
  { name: "fs.rm", shape: "qualified-function", mode: "unlink", pathArgIdx: 0,
    description: "fs.rm — modern fs delete primitive" },
  { name: "fs.rmSync", shape: "qualified-function", mode: "unlink", pathArgIdx: 0,
    description: "fs.rmSync — synchronous modern delete" },
  { name: "fs.truncate", shape: "qualified-function", mode: "truncate", pathArgIdx: 0,
    description: "fs.truncate — empties the log while keeping the file" },
  { name: "fs.truncateSync", shape: "qualified-function", mode: "truncate", pathArgIdx: 0,
    description: "fs.truncateSync — synchronous truncate" },
  { name: "os.remove", shape: "qualified-function", mode: "unlink", pathArgIdx: 0,
    description: "Python os.remove — audit-file deletion" },
  { name: "os.unlink", shape: "qualified-function", mode: "unlink", pathArgIdx: 0,
    description: "Python os.unlink — audit-file deletion" },
  { name: "pathlib.Path.unlink", shape: "qualified-function", mode: "unlink", pathArgIdx: 0,
    description: "Python pathlib unlink — audit-file deletion" },
  { name: "shutil.rmtree", shape: "qualified-function", mode: "unlink", pathArgIdx: 0,
    description: "Python shutil.rmtree — recursive log-directory wipe" },
];

/** Empty-write sinks — `fs.writeFileSync(auditPath, "")` is equivalent to truncate. */
export const K2_EMPTY_WRITE_SINKS: readonly DestructionSink[] = [
  { name: "fs.writeFile", shape: "qualified-function", mode: "truncate", pathArgIdx: 0,
    description: "fs.writeFile with empty content — truncation-by-write" },
  { name: "fs.writeFileSync", shape: "qualified-function", mode: "truncate", pathArgIdx: 0,
    description: "fs.writeFileSync with empty content — truncation-by-write" },
];

// ─── Logger-disable primitives ───────────────────────────────────────────

/**
 * Logger-disable calls (destruction of the LIVE audit trail). Unlike
 * the file-destruction sinks, these do not require an audit-named
 * path — the toggle itself is the compliance violation.
 */
export interface LoggerDisableSink {
  readonly name: string;
  readonly shape: "qualified-function" | "silent-property-assignment" | "level-property-assignment";
  readonly description: string;
}

export const K2_LOGGER_DISABLE_SINKS: readonly LoggerDisableSink[] = [
  { name: "logging.disable", shape: "qualified-function",
    description: "Python logging.disable(logging.CRITICAL) — global framework suppression" },
  { name: "logger.silent", shape: "silent-property-assignment",
    description: "logger.silent = true — pino / winston / bunyan instance-level suppression" },
  { name: "logger.level", shape: "level-property-assignment",
    description: "logger.level = \"silent\" — instance-level suppression" },
  { name: "audit.disable", shape: "qualified-function",
    description: "project-local audit.disable() — application-level suppression" },
];

// ─── Audit-path identifier tokens ────────────────────────────────────────

/**
 * The rule fires when the destruction path argument expression contains
 * at least one of these tokens (case-insensitive substring match). A
 * `.log` / `.audit` file-extension shape also matches.
 *
 * Using a typed registry with a description makes the no-static-patterns
 * guard count this as data rather than a string array.
 */
export interface AuditPathMarker {
  readonly token: string;
  readonly kind: "file-extension" | "directory-segment" | "field-name" | "keyword";
  readonly description: string;
}

export const K2_AUDIT_PATH_MARKERS: readonly AuditPathMarker[] = [
  { token: "audit", kind: "keyword",
    description: "Literal 'audit' in the path — /var/log/audit.log, .audit files" },
  { token: "journal", kind: "keyword",
    description: "systemd journal / journald files" },
  { token: "trace", kind: "keyword",
    description: "Trace-log conventions" },
  { token: "record", kind: "keyword",
    description: "record.log / records.jsonl conventions" },
  { token: "/logs/", kind: "directory-segment",
    description: "/logs/ directory segment — typical log store location" },
  { token: "/log/", kind: "directory-segment",
    description: "/log/ directory segment — typical log store location" },
  { token: "/var/log", kind: "directory-segment",
    description: "Unix /var/log — default system log path" },
  { token: ".log", kind: "file-extension",
    description: ".log file extension" },
  { token: ".audit", kind: "file-extension",
    description: ".audit file extension" },
  { token: ".jsonl", kind: "file-extension",
    description: ".jsonl — append-only log convention" },
  { token: "auditPath", kind: "field-name",
    description: "config.auditPath — typed config field pointing at the audit file" },
  { token: "logPath", kind: "field-name",
    description: "config.logPath — typed config field" },
  { token: "journalPath", kind: "field-name",
    description: "config.journalPath — typed config field" },
  { token: "auditFile", kind: "field-name",
    description: "config.auditFile — typed config field" },
  { token: "logFile", kind: "field-name",
    description: "config.logFile — typed config field" },
];

// ─── Rotation / archive primitives (negative-evidence markers) ───────────

/**
 * When a rotation primitive is observed in the SAME function scope as
 * a destruction sink, severity drops from critical to high — the code
 * MIGHT be a rotation implementation. (It's still a compliance
 * violation to rotate without retention, so the rule does not
 * suppress.)
 */
export interface RotationMarker {
  readonly token: string;
  readonly kind: "function-call" | "comment-intent";
  readonly description: string;
}

export const K2_ROTATION_MARKERS: readonly RotationMarker[] = [
  { token: "rotate", kind: "function-call",
    description: "Function name contains 'rotate' — rotation intent" },
  { token: "archive", kind: "function-call",
    description: "Archive call — retains a copy before deletion" },
  { token: "compress", kind: "function-call",
    description: "Compress call — intermediate rotation step" },
  { token: "gzip", kind: "function-call",
    description: "Gzip call — log-rotation compression" },
  { token: "S3", kind: "function-call",
    description: "S3 upload — archival to immutable storage" },
  { token: "putObject", kind: "function-call",
    description: "S3 putObject / blob upload — archival" },
  { token: "logrotate", kind: "function-call",
    description: "Explicit logrotate reference" },
];
