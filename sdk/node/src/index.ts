/**
 * index.ts — public entry point for @revoc-io/sdk.
 *
 *     import { RevocOpenAI } from "@revoc-io/sdk";
 *     const client = new RevocOpenAI({ apiKey: "sk-..." });
 *
 * See https://revoc.io/docs for full documentation.
 */

export { RevocOpenAI, type RevocOpenAIOptions } from "./client";
export { GovernanceClient, type GovernanceClientOptions, type AuditEvent, type AuditStats, type PolicyValidationResult, type KillSwitchLogEntry } from "./governance";
export { governedToolCall, RevocMcpError, type GovernedToolCallOptions, type McpBlockData } from "./mcp";
export {
  RevocGovernanceError,
  RevocKillSwitchError,
  RevocDepthExceededError,
  RevocRateLimitError,
  REVOC_DASHBOARD_HEADER,
  REVOC_CLIENT_HEADER,
  REVOC_CLIENT_NAME,
  type RevocErrorDetail,
} from "./types";

export const VERSION = "1.0.0";
