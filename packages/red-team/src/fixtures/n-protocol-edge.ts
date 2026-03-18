import type { RuleFixtureSet } from "../types.js";

const base = {
  server: { id: "test", name: "test-server", description: null, github_url: null },
  tools: [],
  dependencies: [],
  connection_metadata: null,
};

function srcCtx(source_code: string) {
  return { ...base, source_code };
}

// ── N1: JSON-RPC Batch Request Abuse ─────────────────────────────────────────
export const N1: RuleFixtureSet = {
  rule_id: "N1",
  rule_name: "JSON-RPC Batch Request Abuse",
  fixtures: [
    {
      description: "Array.isArray check on body with iteration and no length guard",
      context: srcCtx(`if (Array.isArray(body)) {
  body.forEach(msg => processMessage(msg));
}`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CometBFT Issue #2867 — unbounded batch size enables DoS",
    },
    {
      description: "JSON.parse result iterated via map without batch limit",
      context: srcCtx(`const messages = JSON.parse(rawBody);
messages.map(m => handleRpc(m));`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python isinstance list check without len guard",
      context: srcCtx(`if isinstance(request, list):
    for item in request:
        handle_request(item)`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Promise.all on batch.map without concurrency limit",
      context: srcCtx(`const results = await Promise.all(batch.map(req => execute(req)));`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: batch array checked with length limit before processing",
      context: srcCtx(`if (Array.isArray(body) && body.length < MAX_BATCH) {
  body.forEach(msg => processMessage(msg));
}`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: test file with batch request mock",
      context: srcCtx(`// test.spec.ts
describe('batch handling', () => {
  it('processes batch', () => {
    const batch = [{ jsonrpc: '2.0', method: 'ping', id: 1 }];
    expect(Array.isArray(batch)).toBe(true);
  });
});`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── N2: JSON-RPC Notification Flooding ───────────────────────────────────────
export const N2: RuleFixtureSet = {
  rule_id: "N2",
  rule_name: "JSON-RPC Notification Flooding",
  fixtures: [
    {
      description: "sendNotification in loop without rate limiting",
      context: srcCtx(`for (const item of updates) {
  sendNotification({ method: 'update', params: item });
}`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "Parity JSON-RPC DoS resilience spec — unbounded notification floods",
    },
    {
      description: "setInterval firing notifications without clearInterval or limit",
      context: srcCtx(`setInterval(() => {
  notify({ event: 'heartbeat', data: getStatus() });
}, 100);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "SSE res.write event stream without buffer check",
      context: srcCtx(`function streamEvents(res) {
  events.forEach(event => {
    res.write(\`data: \${JSON.stringify(event)}\\n\\n\`);
  });
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "WebSocket send in forEach without drain or backpressure check",
      context: srcCtx(`items.forEach(item => {
  ws.send(JSON.stringify({ notification: item }));
});`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: notification sender checks queue length before sending",
      context: srcCtx(`if (queue.length < MAX_QUEUE_SIZE) {
  sendNotification({ method: 'update', params: data });
} else {
  applyBackpressure();
}`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: rate-limited notification system with throttle",
      context: srcCtx(`const throttledNotify = throttle(sendNotification, 1000);
throttledNotify({ method: 'progress', params: status });`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── N3: JSON-RPC Request ID Collision ────────────────────────────────────────
export const N3: RuleFixtureSet = {
  rule_id: "N3",
  rule_name: "JSON-RPC Request ID Collision",
  fixtures: [
    {
      description: "Auto-incrementing integer request ID counter",
      context: srcCtx(`let requestId = 0;
function sendRequest(method, params) {
  return transport.send({ jsonrpc: '2.0', method, params, id: ++requestId });
}`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CVE-2025-6515 — predictable session/request IDs enable response spoofing",
    },
    {
      description: "Python self._request_id auto-increment",
      context: srcCtx(`class McpClient:
    def __init__(self):
        self._request_id = 0

    def send(self, method):
        self._request_id += 1
        return {"jsonrpc": "2.0", "method": method, "id": self._request_id}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Date.now() used as request ID (predictable)",
      context: srcCtx(`const requestId = Date.now();
transport.send({ jsonrpc: '2.0', method: 'tools/list', id: requestId });`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Math.random for request ID (insufficiently random)",
      context: srcCtx(`const requestId = Math.floor(Math.random() * 100000);
send({ id: requestId, method: 'ping' });`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: crypto.randomUUID for request IDs",
      context: srcCtx(`const requestId = crypto.randomUUID();
transport.send({ jsonrpc: '2.0', method: 'tools/list', id: requestId });`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: nanoid for request IDs",
      context: srcCtx(`import { nanoid } from 'nanoid';
const id = nanoid();
send({ jsonrpc: '2.0', method: 'ping', id });`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── N4: JSON-RPC Error Object Injection ──────────────────────────────────────
export const N4: RuleFixtureSet = {
  rule_id: "N4",
  rule_name: "JSON-RPC Error Object Injection",
  fixtures: [
    {
      description: "Error message constructed from request parameter input",
      context: srcCtx(`function handleToolCall(req) {
  if (!req.params.name) {
    return { error: { code: -32600, message: req.body.input } };
  }
}`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CyberArk ATPA (2025) — error responses as injection vectors for AI clients",
    },
    {
      description: "McpError with message from external data",
      context: srcCtx(`try {
  await executeTool(params);
} catch (e) {
  throw new McpError(-32603, e.message);
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Error data field set from result without sanitization",
      context: srcCtx(`const err = new JsonRpcError(-32000, 'Tool failed');
err.data = result.output;
return err;`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python McpError with f-string from external data",
      context: srcCtx(`raise McpError(code=-32603, message=f"Failed: {result.output}")`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: predefined error messages with no dynamic content",
      context: srcCtx(`return { error: { code: -32601, message: 'Method not found' } };`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: error message sanitized before inclusion",
      context: srcCtx(`const msg = sanitize(e.message);
return { error: { code: -32603, message: msg } };`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── N5: Capability Downgrade Deception ───────────────────────────────────────
export const N5: RuleFixtureSet = {
  rule_id: "N5",
  rule_name: "Capability Downgrade Deception",
  fixtures: [
    {
      description: "Server declares only tools capability but has tools referencing resources",
      context: {
        ...base,
        tools: [
          { name: "list_resources", description: "Lists available resources from the store", input_schema: null },
          { name: "subscribe", description: "Subscribe to resource updates", input_schema: null },
        ],
        declared_capabilities: { tools: true },
      },
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "MCP spec 2025-03-26 — capability negotiation mismatch enables stealth escalation",
    },
    {
      description: "Server declares only tools but tool descriptions mention LLM completion and sampling",
      context: {
        ...base,
        tools: [
          { name: "analyze_text", description: "Uses sampling and LLM completion to analyze text", input_schema: null },
          { name: "generate", description: "Uses createMessage to generate AI responses", input_schema: null },
        ],
        declared_capabilities: { tools: true },
      },
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Server declares only tools but has get_prompt and PromptMessage tools",
      context: {
        ...base,
        tools: [
          { name: "get_prompt", description: "Retrieves a PromptMessage template from the prompt library", input_schema: null },
          { name: "list_prompts", description: "Lists all available prompt templates", input_schema: null },
        ],
        declared_capabilities: { tools: true },
      },
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: server declares tools and resources, and has both types of operations",
      context: {
        ...base,
        tools: [
          { name: "list_resources", description: "Lists available resources", input_schema: null },
          { name: "read_file", description: "Reads a local file", input_schema: null },
        ],
        declared_capabilities: { tools: true, resources: true },
      },
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: server declares only tools and all tools are standard CRUD with no capability references",
      context: {
        ...base,
        tools: [
          { name: "create_item", description: "Creates a new item in the database", input_schema: null },
          { name: "read_item", description: "Reads an item by ID", input_schema: null },
        ],
        declared_capabilities: { tools: true },
      },
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── N6: SSE Reconnection Hijacking ───────────────────────────────────────────
export const N6: RuleFixtureSet = {
  rule_id: "N6",
  rule_name: "SSE Reconnection Hijacking",
  fixtures: [
    {
      description: "Last-Event-ID read from request headers without auth validation",
      context: srcCtx(`const lastEventId = req.headers['last-event-id'];
if (lastEventId) {
  resumeStream(res, lastEventId);
}`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CVE-2025-6515 — SSE session hijacking via predictable event IDs",
    },
    {
      description: "EventSource created without auth credentials on reconnection",
      context: srcCtx(`const eventSource = new EventSource('/mcp/sse');
eventSource.onopen = () => {
  console.log('SSE connected');
};`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Sequential integer event IDs (predictable for hijacking)",
      context: srcCtx(`let eventCounter = 0;
function sendEvent(res, data) {
  const eventId = ++eventCounter;
  res.write(\`id: \${eventId}\\ndata: \${data}\\n\\n\`);
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "SSE retry set to aggressive low interval without jitter",
      context: srcCtx(`res.write("retry: 50\\n");
res.write(\`data: \${JSON.stringify(event)}\\n\\n\`);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: SSE with withCredentials and session auth verification",
      context: srcCtx(`const evtSource = new EventSource('/mcp/sse', { withCredentials: true });
// Server verifies auth cookie on every reconnection
function verifyAuth(req) {
  return validateSession(req.cookies.session);
}`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: SSE reconnection with checkToken validation",
      context: srcCtx(`app.get('/sse', (req, res) => {
  if (!checkToken(req.headers.authorization)) return res.status(401).end();
  const lastId = req.headers['last-event-id'];
  verifyAuth(req);
  resumeStream(res, lastId);
});`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── N7: Progress Token Prediction and Injection ──────────────────────────────
export const N7: RuleFixtureSet = {
  rule_id: "N7",
  rule_name: "Progress Token Prediction and Injection",
  fixtures: [
    {
      description: "Sequential integer progress tokens",
      context: srcCtx(`let counter = 0;
function startOperation() {
  const progressToken = ++counter;
  return { _meta: { progressToken } };
}`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "MCP spec 2025-03-26 Section 5.1 — predictable progress tokens enable spoofed UI",
    },
    {
      description: "Progress notification sent using token from request params without validation",
      context: srcCtx(`function sendProgress(token, progress, total) {
  sendNotification({
    method: 'notifications/progress',
    params: { progressToken: token, progress, total }
  });
}
// Called with: sendProgress(req.params.token, 50, 100);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Broadcasting progress to all clients instead of the originator",
      context: srcCtx(`clients.forEach(client => {
  client.send(JSON.stringify({ method: 'notifications/progress', params: { progress: 50, total: 100 } }));
});`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Progress total from untrusted params without clamping",
      context: srcCtx(`const total = params.progressTotal;
sendProgress({ progressToken: token, progress: current, total });`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: progress tokens generated with crypto.randomUUID",
      context: srcCtx(`const progressToken = crypto.randomUUID();
pendingRequests.set(progressToken, { requestId, startedAt: Date.now() });`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: progress token validated against active request map",
      context: srcCtx(`function validateToken(token) {
  return pendingRequests.has(token) && uuid.validate(token);
}
if (validateToken(progressToken)) {
  sendProgress(progressToken, current, total);
}`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── N8: Cancellation Race Condition ──────────────────────────────────────────
export const N8: RuleFixtureSet = {
  rule_id: "N8",
  rule_name: "Cancellation Race Condition",
  fixtures: [
    {
      description: "Cancel handler deletes partial results without checking committed state",
      context: srcCtx(`function handleCancel(requestId) {
  const op = operations.get(requestId);
  if (op) {
    op.delete();
    operations.delete(requestId);
  }
}`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CWE-367 TOCTOU — cancellation race leaves inconsistent state",
    },
    {
      description: "AbortSignal used with write operation without transaction guard",
      context: srcCtx(`const controller = new AbortController();
async function writeData(data) {
  if (controller.signal.aborted) return;
  await db.insert(data);
  await fs.writeFile('/data/output.json', JSON.stringify(data));
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Two-phase operation without rollback on cancel between phases",
      context: srcCtx(`async function processTransaction(data) {
  await phase1(data);
  await phase2(data);
  // No rollback if cancelled between phase1 and phase2
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: cancel handler checks committed flag and uses transaction rollback",
      context: srcCtx(`async function handleCancel(requestId) {
  const op = operations.get(requestId);
  if (op && !op.committed) {
    await transaction.rollback();
    operations.delete(requestId);
  }
}`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: mutable operations wrapped in atomic transaction with finally cleanup",
      context: srcCtx(`async function processRequest(data) {
  const tx = await db.transaction();
  try {
    await tx.insert(data);
    await tx.commit();
  } catch (e) {
    await tx.rollback();
  } finally {
    cleanup(data);
  }
}`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── N9: MCP Logging Protocol Injection ───────────────────────────────────────
export const N9: RuleFixtureSet = {
  rule_id: "N9",
  rule_name: "MCP Logging Protocol Injection",
  fixtures: [
    {
      description: "sendLogMessage with unsanitized tool output in data field",
      context: srcCtx(`const result = await executeTool(params);
sendLogMessage({ level: 'info', data: result.output });`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CWE-117 Log Injection — MCP log messages processed by AI clients as context",
    },
    {
      description: "Python logger with f-string embedding tool result",
      context: srcCtx(`result = await tool.execute(params)
logger.info(f"Tool completed: {result.output}")`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Template literal in logger.info with response data",
      context: srcCtx(`const data = await fetchFromApi(url);
logger.info(\`API response: \${response.body}\`);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "MCP server sendLoggingMessage with data from request params",
      context: srcCtx(`server.sendLoggingMessage({
  level: 'info',
  data: req.params.toolOutput,
});`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: log messages use predefined templates with no external data",
      context: srcCtx(`logger.info('Tool execution started');
logger.info('Tool execution completed successfully');`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: content sanitized before logging",
      context: srcCtx(`const cleanOutput = sanitize(result.output);
logger.info({ event: 'tool_complete', data: cleanOutput });`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── N10: Incomplete Handshake Denial of Service ──────────────────────────────
export const N10: RuleFixtureSet = {
  rule_id: "N10",
  rule_name: "Incomplete Handshake Denial of Service",
  fixtures: [
    {
      description: "WebSocket connection handler without handshake timeout",
      context: srcCtx(`wss.on('connection', (ws) => {
  ws.on('message', (data) => {
    handleMessage(ws, data);
  });
});`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "Slowloris DoS (CWE-400) — incomplete MCP handshake exhausts connection slots",
    },
    {
      description: "createServer without maxConnections limit",
      context: srcCtx(`const server = http.createServer((req, res) => {
  handleHttpRequest(req, res);
});
server.listen(3000);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Await initialize without timeout or deadline",
      context: srcCtx(`async function onConnect(transport) {
  const initResult = await handleInitialize(transport);
  startSession(initResult);
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: handshake timeout enforced with setTimeout",
      context: srcCtx(`wss.on('connection', (ws) => {
  const handshakeTimeout = setTimeout(() => ws.close(), 30000);
  ws.on('message', (data) => {
    clearTimeout(handshakeTimeout);
    handleMessage(ws, data);
  });
});`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: server with maxConnections and initTimeout",
      context: srcCtx(`const server = http.createServer(handler);
server.maxConnections = 100;
const initTimeout = 30000;
server.listen(3000);`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── N11: Protocol Version Downgrade Attack ───────────────────────────────────
export const N11: RuleFixtureSet = {
  rule_id: "N11",
  rule_name: "Protocol Version Downgrade Attack",
  fixtures: [
    {
      description: "Server echoes client-requested protocol version without validation",
      context: srcCtx(`function handleInit(req) {
  const result = {};
  result.protocolVersion = req.params.protocolVersion;
  return result;
}`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "MCP spec version history — downgrade strips annotation and elicitation safety features",
    },
    {
      description: "Server hardcodes fallback to oldest protocol version",
      context: srcCtx(`const serverConfig = {
  protocolVersion: '2024-11-05',
  serverInfo: { name: 'legacy-server', version: '1.0.0' },
};`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Version negotiation picks minimum of client and server versions",
      context: srcCtx(`function negotiate(clientVersion, serverVersion) {
  return Math.min(clientVersion, serverVersion);
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: server checks client version against SUPPORTED_VERSIONS array",
      context: srcCtx(`const SUPPORTED_VERSIONS = ['2025-03-26', '2025-06-18'];
function handleInit(req) {
  if (!SUPPORTED_VERSIONS.includes(req.params.protocolVersion)) {
    throw new McpError(-32600, 'Unsupported protocol version');
  }
  return { protocolVersion: req.params.protocolVersion };
}`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: minimum version enforcement",
      context: srcCtx(`const MIN_PROTOCOL_VERSION = '2025-03-26';
if (compareVersions(clientVersion, MIN_PROTOCOL_VERSION) < 0) {
  throw new Error('Protocol version too old');
}`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── N12: Resource Subscription Content Mutation ──────────────────────────────
export const N12: RuleFixtureSet = {
  rule_id: "N12",
  rule_name: "Resource Subscription Content Mutation",
  fixtures: [
    {
      description: "Resource update handler uses new content without re-validation",
      context: srcCtx(`client.on('resources/updated', async (notification) => {
  const content = await readResource(notification.uri);
  agentContext.addContent(content.text);
});`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "TOCTOU CWE-367 — resource content changes between validation and use",
    },
    {
      description: "Subscription handler replaces content on update without scanning",
      context: srcCtx(`function subscribe(resourceUri, callback) {
  watcher.observe(resourceUri, (update) => {
    callback({ content: update.data });
  });
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python on_resource_updated sets content from event without validation",
      context: srcCtx(`async def on_resource_updated(event):
    content = event.new_content
    context.data = content
    await process(content)`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: subscription update handler re-scans for injection before use",
      context: srcCtx(`client.on('resources/updated', async (notification) => {
  const content = await readResource(notification.uri);
  const safe = sanitizeContent(content);
  validateResource(safe);
  agentContext.addContent(safe.text);
});`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: resource changes trigger full scanForInjection re-analysis",
      context: srcCtx(`watcher.on('change', async (uri) => {
  const content = await read(uri);
  await scanForInjection(content);
  cache.set(uri, content);
});`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── N13: HTTP Chunked Transfer Smuggling ─────────────────────────────────────
export const N13: RuleFixtureSet = {
  rule_id: "N13",
  rule_name: "HTTP Chunked Transfer Smuggling",
  fixtures: [
    {
      description: "Manual chunked encoding parser for MCP endpoint",
      context: srcCtx(`function chunked_parse(req) {
  let body = '';
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => processBody(body));
}`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CWE-444 — HTTP request smuggling via chunked encoding desync",
    },
    {
      description: "Both Content-Length and Transfer-Encoding headers present",
      context: srcCtx(`app.use((req, res, next) => {
  const contentLength = req.headers['content-length'];
  const transferEncoding = req.headers['transfer-encoding'];
  if (contentLength && transferEncoding) {
    // Process using content-length
  }
  next();
});`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Raw HTTP socket parsing with CRLF splitting",
      context: srcCtx(`const server = net.createServer((socket) => {
  socket.on('data', (data) => {
    const parts = data.toString().split('\\r\\n');
    const headers = parts.slice(0, parts.indexOf('\\r\\n\\r\\n'));
  });
});`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: MCP server uses Express framework for HTTP handling",
      context: srcCtx(`import express from 'express';
const app = express();
app.use(express.json());
app.post('/mcp', mcpHandler);`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: using Fastify with built-in HTTP parsing",
      context: srcCtx(`import Fastify from 'fastify';
const server = Fastify({ logger: true });
server.post('/mcp', mcpHandler);`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── N14: Trust-On-First-Use Bypass (TOFU) ────────────────────────────────────
export const N14: RuleFixtureSet = {
  rule_id: "N14",
  rule_name: "Trust-On-First-Use Bypass (TOFU)",
  fixtures: [
    {
      description: "Approved servers stored by name only without content hashing",
      context: srcCtx(`const trustedServers = {};
function approveServer(config) {
  trustedServers[config.name] = true;
}`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CVE-2025-54136 (Cursor MCPoison) — TOFU bypass enables silent config swap",
    },
    {
      description: "MCP config file loaded without integrity verification",
      context: srcCtx(`async function loadConfig() {
  const config = await readJSON('.mcp/config.json');
  return parseConfig(config);
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Server trust approved without hash or checksum",
      context: srcCtx(`function trustServer(server) {
  approvedConfigs.add(server.id);
  saveApprovedList(approvedConfigs);
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python trusted_configs append without hashlib verification",
      context: srcCtx(`trusted_configs = []
def approve(config):
    trusted_configs.append(config.name)
    save_trusted(trusted_configs)`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: SHA-256 hash computed at approval and verified on every load",
      context: srcCtx(`function approveServer(config) {
  const hash = crypto.createHash('sha256').update(JSON.stringify(config)).digest('hex');
  trustedServers[config.name] = { hash, approvedAt: Date.now() };
}
function checkIntegrity(config) {
  const currentHash = crypto.createHash('sha256').update(JSON.stringify(config)).digest('hex');
  return trustedServers[config.name]?.hash === currentHash;
}`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: config changes trigger re-approval with fingerprint comparison",
      context: srcCtx(`const fingerprint = computeFingerprint(config);
if (storedFingerprint !== fingerprint) {
  await promptUserForReapproval(config, fingerprint);
}`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── N15: JSON-RPC Method Name Confusion ──────────────────────────────────────
export const N15: RuleFixtureSet = {
  rule_id: "N15",
  rule_name: "JSON-RPC Method Name Confusion",
  fixtures: [
    {
      description: "Dynamic dispatch via bracket notation from request method",
      context: srcCtx(`function handleRequest(req) {
  return handler[req.body.method](req.body.params);
}`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CWE-749 — exposed dangerous method via dynamic dispatch",
    },
    {
      description: "tools/call dispatches tool name from params without checking registered list",
      context: srcCtx(`app.post('/tools/call', async (req, res) => {
  const result = await executeTool(req.params.name, req.params.arguments);
  res.json(result);
});`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python getattr dynamic dispatch from request method",
      context: srcCtx(`class McpServer:
    async def handle(self, request):
        handler = getattr(self, request.method)
        return await handler(request.params)`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: explicit switch statement for method routing",
      context: srcCtx(`function route(method, params) {
  switch (method) {
    case 'initialize': return handleInit(params);
    case 'tools/list': return handleToolsList(params);
    case 'tools/call': return handleToolsCall(params);
    default: return { error: { code: -32601, message: 'Method not found' } };
  }
}`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: tools/call validates against registeredTools before dispatch",
      context: srcCtx(`app.post('/tools/call', async (req, res) => {
  if (!registeredTools.has(req.params.name)) {
    return res.status(404).json({ error: 'Unknown tool' });
  }
  const result = await executeTool(req.params.name, req.params.arguments);
  res.json(result);
});`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

export const ALL_N_FIXTURES: RuleFixtureSet[] = [
  N1, N2, N3, N4, N5, N6, N7, N8, N9, N10,
  N11, N12, N13, N14, N15,
];
