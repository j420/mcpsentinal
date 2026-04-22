export interface RiskFragment {
  readonly fragment: string;
  readonly label: string;
  readonly variant:
    | "reconnect"
    | "last_event_id"
    | "session_in_url"
    | "event_log_offset";
}

export const RISK_FRAGMENTS: Readonly<Record<string, RiskFragment>> = {
  eventsource: {
    fragment: "eventsource",
    label: "EventSource transport / SSE",
    variant: "reconnect",
  },
  reconnect: {
    fragment: "reconnect",
    label: "reconnection handler",
    variant: "reconnect",
  },
  "last-event-id": {
    fragment: "last-event-id",
    label: "Last-Event-ID header read",
    variant: "last_event_id",
  },
  lasteventid: {
    fragment: "lasteventid",
    label: "lastEventId variable",
    variant: "last_event_id",
  },
  sessionid: {
    fragment: "sessionid",
    label: "sessionId variable",
    variant: "session_in_url",
  },
  session_id: {
    fragment: "session_id",
    label: "session_id variable",
    variant: "session_in_url",
  },
};

/** If any of these fragments appears nearby, treat as mitigation present. */
export const AUTH_FRAGMENTS: Readonly<Record<string, string>> = {
  verify: "verify call",
  validate: "validate call",
  hmac: "hmac check",
  "jwt.verify": "JWT verify",
  authenticate: "authenticate call",
  "timing-safe": "timing-safe comparison",
};

export const N6_CONFIDENCE_CAP = 0.8;
export const N6_AUTH_WINDOW = 6;
