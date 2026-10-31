/**
 * types.ts — typed exceptions raised when REVOC governs a request.
 *
 * These map 1:1 onto the `error.code` values produced by `RevocErrorResponse`
 * (SPEC.md Section 7.5 / types/openai.rs). `RevocOpenAI` inspects the JSON
 * error body returned by the proxy and throws the matching error class so
 * application code can branch on governance outcomes without parsing raw
 * HTTP responses.
 */

/** Fields shared by REVOC governance error payloads. */
export interface RevocErrorDetail {
  code: string;
  message: string;
  type: string;
  blocked_by?: string | null;
  rules?: string[] | null;
  trace_id: string;
  dashboard_url: string;
  documentation_url?: string | null;
}

/**
 * Thrown when REVOC blocks a request due to a policy violation.
 *
 * Corresponds to `error.code === "REVOC_GOVERNANCE_BLOCK"`.
 */
export class RevocGovernanceError extends Error {
  public readonly decision: string;
  public readonly blockedBy: string | null;
  public readonly rules: string[];
  public readonly traceId: string;
  public readonly dashboardUrl: string;
  public readonly documentationUrl: string | null;

  constructor(opts: {
    reason: string;
    decision: string;
    blockedBy: string | null;
    rules: string[];
    traceId: string;
    dashboardUrl: string;
    documentationUrl?: string | null;
  }) {
    super(`REVOC blocked [${opts.blockedBy}]: ${opts.reason}\nTrace: ${opts.dashboardUrl}`);
    this.name = "RevocGovernanceError";
    this.decision = opts.decision;
    this.blockedBy = opts.blockedBy;
    this.rules = opts.rules;
    this.traceId = opts.traceId;
    this.dashboardUrl = opts.dashboardUrl;
    this.documentationUrl = opts.documentationUrl ?? null;
    Object.setPrototypeOf(this, RevocGovernanceError.prototype);
  }
}

/**
 * Thrown when the emergency kill-switch is active.
 *
 * Corresponds to `error.code === "REVOC_KILL_SWITCH_ACTIVE"`.
 */
export class RevocKillSwitchError extends Error {
  public readonly scope: string;
  public readonly dashboardUrl: string;

  constructor(opts: { scope: string; dashboardUrl: string }) {
    super("REVOC emergency stop active. Contact your AI platform team.");
    this.name = "RevocKillSwitchError";
    this.scope = opts.scope;
    this.dashboardUrl = opts.dashboardUrl;
    Object.setPrototypeOf(this, RevocKillSwitchError.prototype);
  }
}

/**
 * Thrown when governance depth reaches the configured maximum (10).
 *
 * Corresponds to `error.code === "REVOC_GOVERNANCE_DEPTH_EXCEEDED"`.
 */
export class RevocDepthExceededError extends Error {
  public readonly depth: number;
  public readonly maxDepth: number;

  constructor(opts: { depth: number; maxDepth?: number }) {
    const maxDepth = opts.maxDepth ?? 10;
    super(`Governance depth ${opts.depth}/${maxDepth} reached. Possible infinite agent loop.`);
    this.name = "RevocDepthExceededError";
    this.depth = opts.depth;
    this.maxDepth = maxDepth;
    Object.setPrototypeOf(this, RevocDepthExceededError.prototype);
  }
}

/**
 * Thrown when the caller has exceeded their configured rate limit.
 *
 * Corresponds to `error.code === "REVOC_RATE_LIMIT_EXCEEDED"`.
 */
export class RevocRateLimitError extends Error {
  public readonly retryAfterSecs: number;

  constructor(opts: { retryAfterSecs: number }) {
    super(`REVOC rate limit exceeded. Retry after ${opts.retryAfterSecs} seconds.`);
    this.name = "RevocRateLimitError";
    this.retryAfterSecs = opts.retryAfterSecs;
    Object.setPrototypeOf(this, RevocRateLimitError.prototype);
  }
}

/** Header REVOC sets on every response — points to the trace's dashboard view. */
export const REVOC_DASHBOARD_HEADER = "X-Revoc-Dashboard";

/** Header set by SDK clients to identify themselves to the proxy. */
export const REVOC_CLIENT_HEADER = "X-Revoc-Client";

/** Value sent in the `X-Revoc-Client` header by this SDK. */
export const REVOC_CLIENT_NAME = "@revoc-io/sdk";
