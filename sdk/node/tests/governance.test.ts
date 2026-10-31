/**
 * governance.test.ts — GovernanceClient HTTP wrapper behavior using a
 * mocked global `fetch`.
 */

import { GovernanceClient } from "../src";

const BASE_URL = "http://revoc.local:3000";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("GovernanceClient", () => {
  let fetchMock: jest.Mock;

  beforeEach(() => {
    fetchMock = jest.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  it("sends an Authorization header when an API key is configured", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ total: 0, blocked: 0, redacted: 0, allowed: 0, top_rules: [], top_callers: [] })
    );
    const client = new GovernanceClient({ baseUrl: BASE_URL, apiKey: "admin-key" });

    await client.getAuditStats(new Date("2026-06-06T00:00:00Z"), new Date("2026-06-07T00:00:00Z"));

    const [, init] = fetchMock.mock.calls[0];
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer admin-key");
  });

  it("hits /api/v1/audit/stats with ISO timestamps", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ total: 5, blocked: 1, redacted: 2, allowed: 2, top_rules: [], top_callers: [] })
    );
    const client = new GovernanceClient({ baseUrl: BASE_URL });
    const stats = await client.getAuditStats(
      new Date("2026-06-06T00:00:00Z"),
      new Date("2026-06-07T00:00:00Z")
    );

    const [url] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/api/v1/audit/stats");
    expect(String(url)).toContain("start_time=");
    expect(stats.total).toBe(5);
  });

  it("validatePolicy posts yaml_content and returns the validation result", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ is_valid: true, errors: [] }));
    const client = new GovernanceClient({ baseUrl: BASE_URL });

    const result = await client.validatePolicy("apiVersion: revoc.io/v1\n");

    expect(result.is_valid).toBe(true);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/api/v1/policies/validate");
    expect(JSON.parse(init.body as string)).toEqual({ yaml_content: "apiVersion: revoc.io/v1\n" });
  });

  it("activateKillSwitch posts scope and reason", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ scope: "global", action: "activate" }));
    const client = new GovernanceClient({ baseUrl: BASE_URL, apiKey: "admin-key" });

    const entry = await client.activateKillSwitch("global", "incident-123");

    expect(entry.action).toBe("activate");
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/api/v1/emergency/kill-switch/activate");
    const body = JSON.parse(init.body as string);
    expect(body.scope).toBe("global");
    expect(body.reason).toBe("incident-123");
  });

  it("deactivateKillSwitch posts the scope only", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ scope: "org", action: "deactivate" }));
    const client = new GovernanceClient({ baseUrl: BASE_URL });

    const entry = await client.deactivateKillSwitch("org");

    expect(entry.action).toBe("deactivate");
    const [, init] = fetchMock.mock.calls[0];
    const body = JSON.parse(init.body as string);
    expect(body).toEqual({ scope: "org" });
  });

  it("throws when the admin-api responds with a non-2xx status", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ detail: "forbidden" }, 403));
    const client = new GovernanceClient({ baseUrl: BASE_URL });

    await expect(client.getAuditEvents()).rejects.toThrow(/HTTP 403/);
  });
});
