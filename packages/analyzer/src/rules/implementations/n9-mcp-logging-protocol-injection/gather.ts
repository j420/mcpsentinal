import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  MCP_LOG_SURFACES,
  LOGGER_SURFACES,
  USER_INPUT_FRAGS,
  SANITISER_FRAGS,
  type LogSurface,
  type UserInputFrag,
} from "./data/log-surfaces.js";

export interface LogInjectSite {
  location: Location;
  line: number;
  line_text: string;
  user_input: UserInputFrag;
  log_surface: LogSurface;
  sanitised_nearby: boolean;
}

export interface N9Gathered {
  sites: LogInjectSite[];
}

function hasFrag(lineLc: string, frags: Readonly<Record<string, unknown>>):
  | string
  | null {
  for (const k of Object.keys(frags)) {
    if (lineLc.indexOf(k) !== -1) return k;
  }
  return null;
}

export function gatherN9(context: AnalysisContext): N9Gathered {
  const source = context.source_code;
  if (!source) return { sites: [] };
  const lcSrc = source.toLowerCase();
  if (lcSrc.indexOf("__tests__") !== -1 || lcSrc.indexOf(".test.") !== -1)
    return { sites: [] };

  const lines = source.split("\n");
  const sites: LogInjectSite[] = [];
  for (let i = 0; i < lines.length; i++) {
    const lc = lines[i].toLowerCase();
    const userKey = hasFrag(lc, USER_INPUT_FRAGS);
    if (!userKey) continue;

    const mcpKey = hasFrag(lc, MCP_LOG_SURFACES);
    const loggerKey = hasFrag(lc, LOGGER_SURFACES);
    let surface: LogSurface | null = null;
    if (mcpKey) surface = MCP_LOG_SURFACES[mcpKey];
    else if (loggerKey) surface = LOGGER_SURFACES[loggerKey];
    if (!surface) continue;

    // sanitiser on the same line demotes
    const sanitised = hasFrag(lc, SANITISER_FRAGS) !== null;

    sites.push({
      location: { kind: "source", file: "<aggregated>", line: i + 1 },
      line: i + 1,
      line_text: lines[i].trim().slice(0, 160),
      user_input: USER_INPUT_FRAGS[userKey],
      log_surface: surface,
      sanitised_nearby: sanitised,
    });
  }
  return { sites };
}
