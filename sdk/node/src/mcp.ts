/**
 * mcp.ts — helpers for governed Model Context Protocol tool calls.
 *
 * REVOC inspects MCP traffic bidirectionally (SPEC.md Section 11, MCP
 * Handler 12-step lifecycle). When a `tools/call` request is blocked, the
 * proxy returns a JSON-RPC error response shaped like `McpBlockResponse`
 * (`{"error": {"code": -32603, "data": {"code": "REVOC_GOVERNANCE_BLOCK", ...}}}`).
 *
 * `governedToolCall` posts a governed `tools/call` request through REVOC and
 * throws `RevocMcpError` when the call was blocked — the upstream MCP server
 * never receives a blocked request (Rule 9, SPEC.md Section 23).
 */

export interface McpBlockData {
  code: string;
  rules: string[];
  trace_id: string;
  dashboard_url: string;
}

/**
 * Thrown when REVOC blocks an MCP `tools/call` request before it reaches the
 * upstream MCP server.
 */
export class RevocMcpError extends Error {
  public readonly code: string;
  public readonly rules: string[];
  public readonly traceId: string;
  public readonly dashboardUrl: string;

  constructor(opts: { message: string; code: string; rules: string[]; traceId: string; dashboardUrl: string }) {
    super(`REVOC blocked MCP tool call [${opts.code}]: ${opts.message}\nTrace: ${opts.dashboardUrl}`);
    this.name = "RevocMcpError";
    this.code = opts.code;
    this.rules = opts.rules;
    this.traceId = opts.traceId;
    this.dashboardUrl = opts.dashboardUrl;
    Object.setPrototypeOf(this, RevocMcpError.prototype);
  }
}

export interface GovernedToolCallOptions {
  baseUrl: string;
  toolName: string;
  arguments: Record<string, unknown>;
  serverId?: string;
  requestId?: string;
  headers?: Record<string, string>;
}

/**
 * POST a `tools/call` JSON-RPC request through the REVOC MCP endpoint.
 *
 * Returns the parsed JSON-RPC response body on success. Throws
 * `RevocMcpError` if REVOC blocked the call.
 */
export async function governedToolCall(options: GovernedToolCallOptions): Promise<Record<string, unknown>> {
  const params: Record<string, unknown> = {
    name: options.toolName,
    arguments: options.arguments,
  };
  if (options.serverId) {
    params.server_id = options.serverId;
  }

  const payload = {
    jsonrpc: "2.0",
    id: options.requestId ?? "1",
    method: "tools/call",
    params,
  };

  const resp = await fetch(`${options.baseUrl.replace(/\/+$/, "")}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(options.headers ?? {}) },
    body: JSON.stringify(payload),
  });
  const body = (await resp.json()) as {
    error?: { message?: string; data?: McpBlockData };
    [key: string]: unknown;
  };

  const data = body.error?.data;
  if (data && data.code === "REVOC_GOVERNANCE_BLOCK") {
    throw new RevocMcpError({
      message: body.error?.message ?? "",
      code: data.code,
      rules: data.rules ?? [],
      traceId: data.trace_id,
      dashboardUrl: data.dashboard_url,
    });
  }
  return body;
}
