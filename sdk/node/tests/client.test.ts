/**
 * client.test.ts — RevocOpenAI behavior: base URL resolution, headers,
 * error-class translation, and env-based auto-configuration.
 */

import {
  RevocOpenAI,
  RevocGovernanceError,
  RevocKillSwitchError,
  RevocDepthExceededError,
  RevocRateLimitError,
  REVOC_CLIENT_HEADER,
  REVOC_CLIENT_NAME,
} from "../src";

const REVOC_URL = "http://revoc.local:8080";

describe("RevocOpenAI base URL resolution", () => {
  const originalEnv = process.env.REVOC_BASE_URL;

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.REVOC_BASE_URL;
    } else {
      process.env.REVOC_BASE_URL = originalEnv;
    }
  });

  it("uses revocBaseUrl constructor option when provided", () => {
    delete process.env.REVOC_BASE_URL;
    const client = new RevocOpenAI({ apiKey: "sk-test", revocBaseUrl: REVOC_URL });
    expect(client.baseURL).toBe(REVOC_URL);
  });

  it("falls back to REVOC_BASE_URL environment variable", () => {
    process.env.REVOC_BASE_URL = REVOC_URL;
    const client = new RevocOpenAI({ apiKey: "sk-test" });
    expect(client.baseURL).toBe(REVOC_URL);
  });

  it("prefers explicit revocBaseUrl over the environment variable", () => {
    process.env.REVOC_BASE_URL = "http://other.local:9999";
    const client = new RevocOpenAI({ apiKey: "sk-test", revocBaseUrl: REVOC_URL });
    expect(client.baseURL).toBe(REVOC_URL);
  });
});

describe("RevocOpenAI headers", () => {
  it("sets the X-Revoc-Client header to identify the SDK", () => {
    const client = new RevocOpenAI({ apiKey: "sk-test", revocBaseUrl: REVOC_URL });
    // defaultHeaders is exposed on the underlying OpenAI client config
    const headers = (client as unknown as { _options: { defaultHeaders?: Record<string, string> } })
      ._options?.defaultHeaders;
    expect(headers?.[REVOC_CLIENT_HEADER]).toBe(REVOC_CLIENT_NAME);
  });
});

describe("RevocOpenAI governance getter", () => {
  it("returns a GovernanceClient bound to the proxy base URL", () => {
    const client = new RevocOpenAI({ apiKey: "sk-test", revocBaseUrl: REVOC_URL });
    expect(client.governance).toBeDefined();
    // accessing twice returns the same memoized instance
    expect(client.governance).toBe(client.governance);
  });
});

function buildResponse(status: number, payload: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

describe("REVOC error translation", () => {
  it("constructs RevocGovernanceError with all fields from the response JSON", () => {
    const err = new RevocGovernanceError({
      reason: "Prompt injection detected",
      decision: "block",
      blockedBy: "sec_prompt_injection_v1",
      rules: ["sec_prompt_injection_v1"],
      traceId: "trace-001",
      dashboardUrl: "http://localhost:3000/traces/trace-001",
      documentationUrl: "https://revoc.io/docs/policies/sec_prompt_injection_v1",
    });
    expect(err.blockedBy).toBe("sec_prompt_injection_v1");
    expect(err.rules).toEqual(["sec_prompt_injection_v1"]);
    expect(err.traceId).toBe("trace-001");
    expect(err.message).toContain("http://localhost:3000/traces/trace-001");
    expect(err.message).toContain("sec_prompt_injection_v1");
    expect(err).toBeInstanceOf(Error);
  });

  it("constructs RevocKillSwitchError with a fixed user-facing message", () => {
    const err = new RevocKillSwitchError({ scope: "global", dashboardUrl: "http://localhost:3000/emergency" });
    expect(err.message).toBe("REVOC emergency stop active. Contact your AI platform team.");
    expect(err.scope).toBe("global");
  });

  it("constructs RevocDepthExceededError with parsed depth values", () => {
    const err = new RevocDepthExceededError({ depth: 10, maxDepth: 10 });
    expect(err.depth).toBe(10);
    expect(err.maxDepth).toBe(10);
    expect(err.message).toContain("10/10");
  });

  it("constructs RevocRateLimitError with retry-after seconds", () => {
    const err = new RevocRateLimitError({ retryAfterSecs: 30 });
    expect(err.retryAfterSecs).toBe(30);
    expect(err.message).toContain("30 seconds");
  });

  it("buildResponse helper produces a parseable Response for governance-block payloads", async () => {
    const response = buildResponse(403, {
      error: {
        code: "REVOC_GOVERNANCE_BLOCK",
        message: "Blocked",
        type: "governance_error",
        blocked_by: "secret_block_v1",
        rules: ["secret_block_v1"],
        trace_id: "trace-xyz",
        dashboard_url: "http://localhost:3000/traces/trace-xyz",
      },
    });
    const body = await response.clone().json();
    expect(body.error.code).toBe("REVOC_GOVERNANCE_BLOCK");
    expect(response.status).toBe(403);
  });
});
