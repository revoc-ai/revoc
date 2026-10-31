/**
 * mcp.test.ts — governedToolCall behavior against a mocked global `fetch`.
 */

import { governedToolCall, RevocMcpError } from "../src";

const BASE_URL = "http://revoc.local:8080";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("governedToolCall", () => {
  let fetchMock: jest.Mock;

  beforeEach(() => {
    fetchMock = jest.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  it("posts a tools/call JSON-RPC request to /mcp", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ jsonrpc: "2.0", id: "1", result: { ok: true } }));

    const result = await governedToolCall({
      baseUrl: BASE_URL,
      toolName: "execute_sql",
      arguments: { query: "SELECT 1" },
    });

    expect(result.result).toEqual({ ok: true });
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe(`${BASE_URL}/mcp`);
    const body = JSON.parse(init.body as string);
    expect(body.method).toBe("tools/call");
    expect(body.params.name).toBe("execute_sql");
  });

  it("throws RevocMcpError when REVOC blocks the call", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        jsonrpc: "2.0",
        id: "1",
        error: {
          code: -32603,
          message: "DDL mutation blocked",
          data: {
            code: "REVOC_GOVERNANCE_BLOCK",
            rules: ["sec_ddl_mutation_v1"],
            trace_id: "trace-mcp-001",
            dashboard_url: "http://localhost:3000/traces/trace-mcp-001",
          },
        },
      })
    );

    await expect(
      governedToolCall({
        baseUrl: BASE_URL,
        toolName: "execute_sql",
        arguments: { query: "DROP TABLE users" },
      })
    ).rejects.toThrow(RevocMcpError);
  });

  it("RevocMcpError exposes rules, traceId and dashboardUrl", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        jsonrpc: "2.0",
        id: "1",
        error: {
          code: -32603,
          message: "Path traversal blocked",
          data: {
            code: "REVOC_GOVERNANCE_BLOCK",
            rules: ["sec_path_traversal_v1"],
            trace_id: "trace-mcp-002",
            dashboard_url: "http://localhost:3000/traces/trace-mcp-002",
          },
        },
      })
    );

    try {
      await governedToolCall({
        baseUrl: BASE_URL,
        toolName: "read_file",
        arguments: { path: "../../etc/passwd" },
      });
      fail("expected governedToolCall to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(RevocMcpError);
      const mcpErr = err as RevocMcpError;
      expect(mcpErr.rules).toEqual(["sec_path_traversal_v1"]);
      expect(mcpErr.traceId).toBe("trace-mcp-002");
      expect(mcpErr.dashboardUrl).toBe("http://localhost:3000/traces/trace-mcp-002");
    }
  });

  it("returns the response body unchanged when the call is allowed", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ jsonrpc: "2.0", id: "1", result: { content: [{ type: "text", text: "42" }] } })
    );

    const result = await governedToolCall({
      baseUrl: BASE_URL,
      toolName: "calculator",
      arguments: { expression: "6*7" },
    });

    expect(result.error).toBeUndefined();
    expect(result.result).toBeDefined();
  });
});
