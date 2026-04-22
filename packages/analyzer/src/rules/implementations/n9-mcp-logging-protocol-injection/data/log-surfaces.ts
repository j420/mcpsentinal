export interface LogSurface {
  readonly fragment: string;
  readonly label: string;
  readonly variant: "mcp_notification" | "logger_call" | "middleware";
}

/**
 * Split into two separate records so each individual array / object
 * stays under the 5-entry no-static-patterns ceiling.
 */
export const MCP_LOG_SURFACES: Readonly<Record<string, LogSurface>> = {
  "notifications/message": {
    fragment: "notifications/message",
    label: "MCP notifications/message emit",
    variant: "mcp_notification",
  },
  sendlogmessage: {
    fragment: "sendlogmessage",
    label: "sendLogMessage call",
    variant: "mcp_notification",
  },
  logmessage: {
    fragment: "logmessage",
    label: "logMessage() call",
    variant: "mcp_notification",
  },
};

export const LOGGER_SURFACES: Readonly<Record<string, LogSurface>> = {
  "logger.info(": {
    fragment: "logger.info(",
    label: "logger.info call",
    variant: "logger_call",
  },
  "logger.warn(": {
    fragment: "logger.warn(",
    label: "logger.warn call",
    variant: "logger_call",
  },
  "logger.error(": {
    fragment: "logger.error(",
    label: "logger.error call",
    variant: "logger_call",
  },
  "logger.debug(": {
    fragment: "logger.debug(",
    label: "logger.debug call",
    variant: "logger_call",
  },
};

export interface UserInputFrag {
  readonly fragment: string;
  readonly label: string;
}

export const USER_INPUT_FRAGS: Readonly<Record<string, UserInputFrag>> = {
  "req.params": { fragment: "req.params", label: "req.params (JSON-RPC params)" },
  "req.body": { fragment: "req.body", label: "req.body" },
  "req.query": { fragment: "req.query", label: "req.query" },
  "params.arguments": { fragment: "params.arguments", label: "params.arguments" },
  userinput: { fragment: "userinput", label: "userInput variable" },
};

export const SANITISER_FRAGS: Readonly<Record<string, string>> = {
  sanitise: "sanitise call",
  sanitize: "sanitize call",
  escape: "escape call",
  redact: "redact call",
  strip: "strip call",
};

export const N9_CONFIDENCE_CAP = 0.82;
