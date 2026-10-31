/**
 * client.ts — drop-in OpenAI client subclass routed through REVOC.
 *
 * Usage (zero-code-change beyond the constructor):
 *
 *     import { RevocOpenAI } from "@revoc-io/sdk";
 *     const client = new RevocOpenAI({ apiKey: "sk-..." }); // reads REVOC_BASE_URL
 *     const client = new RevocOpenAI({ apiKey: "sk-...", revocBaseUrl: "http://revoc:8080" });
 *
 * Transparently translates REVOC governance error responses
 * (`RevocErrorResponse`, SPEC.md Section 7.5) into typed exceptions so
 * callers can branch on governance outcomes instead of parsing raw HTTP
 * error bodies. Upstream provider errors (4xx/5xx forwarded verbatim per
 * Rule 8) pass through untouched and are handled by the OpenAI SDK as usual.
 */

import OpenAI, { type ClientOptions } from "openai";

import { GovernanceClient } from "./governance";
import {
  RevocDepthExceededError,
  RevocGovernanceError,
  RevocKillSwitchError,
  RevocRateLimitError,
  REVOC_CLIENT_HEADER,
  REVOC_CLIENT_NAME,
  type RevocErrorDetail,
} from "./types";

export interface RevocOpenAIOptions extends Omit<ClientOptions, "fetch"> {
  /** Explicit REVOC proxy base URL. Falls back to `REVOC_BASE_URL` env var, then `baseURL`. */
  revocBaseUrl?: string;
}

function resolveBaseUrl(
  revocBaseUrl: string | undefined,
  fallback: string | null | undefined
): string | undefined {
  if (revocBaseUrl) return revocBaseUrl;
  const envUrl = process.env.REVOC_BASE_URL;
  if (envUrl) return envUrl;
  return fallback ?? undefined;
}

function parseDepth(message: string): number {
  const match = /\((\d+)\/(\d+)\)/.exec(message);
  if (match) {
    return parseInt(match[1], 10);
  }
  return 10;
}

/**
 * Inspects a Response and throws the matching REVOC exception when the body
 * is a `RevocErrorResponse` (`{"error": {"code": "REVOC_...", ...}}`).
 * No-ops for upstream provider errors, which REVOC forwards verbatim.
 */
async function raiseForRevocError(response: Response): Promise<void> {
  if (response.status < 400) return;

  let payload: { error?: RevocErrorDetail } | undefined;
  try {
    payload = (await response.clone().json()) as { error?: RevocErrorDetail };
  } catch {
    return;
  }
  const error = payload?.error;
  if (!error || typeof error.code !== "string" || !error.code.startsWith("REVOC_")) {
    return;
  }

  switch (error.code) {
    case "REVOC_GOVERNANCE_BLOCK":
      throw new RevocGovernanceError({
        reason: error.message,
        decision: "block",
        blockedBy: error.blocked_by ?? null,
        rules: error.rules ?? [],
        traceId: error.trace_id,
        dashboardUrl: error.dashboard_url,
        documentationUrl: error.documentation_url,
      });
    case "REVOC_KILL_SWITCH_ACTIVE":
      throw new RevocKillSwitchError({
        scope: "global",
        dashboardUrl: error.dashboard_url,
      });
    case "REVOC_GOVERNANCE_DEPTH_EXCEEDED":
      throw new RevocDepthExceededError({
        depth: parseDepth(error.message),
        maxDepth: 10,
      });
    case "REVOC_RATE_LIMIT_EXCEEDED": {
      const retryAfter = parseInt(response.headers.get("retry-after") ?? "0", 10);
      throw new RevocRateLimitError({ retryAfterSecs: Number.isNaN(retryAfter) ? 0 : retryAfter });
    }
    default:
      return;
  }
}

/**
 * Wraps the global `fetch` so every response is inspected for REVOC
 * governance error codes before being handed back to the OpenAI SDK.
 */
function governedFetch(
  input: RequestInfo | URL,
  init?: RequestInit
): Promise<Response> {
  return fetch(input, init).then(async (response) => {
    await raiseForRevocError(response);
    return response;
  });
}

/**
 * Synchronous-style (Promise-based, like all OpenAI Node clients) client
 * transparently governed by REVOC. Drop-in replacement for `OpenAI`.
 */
export class RevocOpenAI extends OpenAI {
  private _revocGovernance: GovernanceClient | null = null;
  private readonly _revocBaseUrl: string;

  constructor(options: RevocOpenAIOptions = {}) {
    const { revocBaseUrl, ...rest } = options;
    const baseURL = resolveBaseUrl(revocBaseUrl, rest.baseURL ?? null);

    super({
      ...rest,
      baseURL,
      defaultHeaders: {
        ...(rest.defaultHeaders ?? {}),
        [REVOC_CLIENT_HEADER]: REVOC_CLIENT_NAME,
      },
      fetch: governedFetch as unknown as ClientOptions["fetch"],
    });

    this._revocBaseUrl = baseURL ?? "";
  }

  /** Lazily-constructed client for the REVOC dashboard / admin-api. */
  get governance(): GovernanceClient {
    if (this._revocGovernance === null) {
      this._revocGovernance = new GovernanceClient({ baseUrl: this._revocBaseUrl });
    }
    return this._revocGovernance;
  }
}
