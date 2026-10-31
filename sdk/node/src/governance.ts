/**
 * governance.ts — client for the REVOC dashboard / admin-api.
 *
 * Exposed via `client.governance` on `RevocOpenAI`. Thin wrappers over the
 * admin-api REST surface (see admin-api/app/routers/*) using the global
 * `fetch` (Node 20+ ships a built-in `fetch`).
 */

export interface AuditEvent {
  [key: string]: unknown;
}

export interface AuditStats {
  total: number;
  blocked: number;
  redacted: number;
  allowed: number;
  top_rules: Array<{ rule_id: string; count: number }>;
  top_callers: Array<{ caller_id: string; count: number }>;
}

export interface PolicyValidationResult {
  is_valid: boolean;
  errors: string[];
}

export interface KillSwitchLogEntry {
  scope: string;
  action: string;
  [key: string]: unknown;
}

export interface GovernanceClientOptions {
  baseUrl: string;
  apiKey?: string;
}

/**
 * Async helper for querying audit data and controlling governance state.
 */
export class GovernanceClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;

  constructor(options: GovernanceClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
  }

  private headers(): Record<string, string> {
    const headers: Record<string, string> = {};
    if (this.apiKey) {
      headers.Authorization = `Bearer ${this.apiKey}`;
    }
    return headers;
  }

  private async getJson<T>(path: string, params?: Record<string, string>): Promise<T> {
    const url = new URL(this.baseUrl + path);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        url.searchParams.set(key, value);
      }
    }
    const resp = await fetch(url.toString(), { headers: this.headers() });
    if (!resp.ok) {
      throw new Error(`REVOC governance request failed: HTTP ${resp.status}`);
    }
    return (await resp.json()) as T;
  }

  private async postJson<T>(path: string, body: unknown): Promise<T> {
    const resp = await fetch(this.baseUrl + path, {
      method: "POST",
      headers: { ...this.headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      throw new Error(`REVOC governance request failed: HTTP ${resp.status}`);
    }
    return (await resp.json()) as T;
  }

  /** Fetch audit events matching the given query parameters. */
  async getAuditEvents(params: Record<string, string> = {}): Promise<AuditEvent[]> {
    return this.getJson<AuditEvent[]>("/api/v1/audit", params);
  }

  /** Fetch aggregate audit statistics for a time window. */
  async getAuditStats(startTime: Date, endTime: Date): Promise<AuditStats> {
    return this.getJson<AuditStats>("/api/v1/audit/stats", {
      start_time: startTime.toISOString(),
      end_time: endTime.toISOString(),
    });
  }

  /** Validate a policy bundle YAML manifest without activating it. */
  async validatePolicy(yamlContent: string): Promise<PolicyValidationResult> {
    return this.postJson<PolicyValidationResult>("/api/v1/policies/validate", {
      yaml_content: yamlContent,
    });
  }

  /** Activate the emergency kill-switch for the given scope ("global" | "org" | "caller"). */
  async activateKillSwitch(scope: string, reason: string): Promise<KillSwitchLogEntry> {
    return this.postJson<KillSwitchLogEntry>("/api/v1/emergency/kill-switch/activate", {
      scope,
      reason,
      activated_by: "revoc-sdk-node",
    });
  }

  /** Deactivate the emergency kill-switch for the given scope. */
  async deactivateKillSwitch(scope: string): Promise<KillSwitchLogEntry> {
    return this.postJson<KillSwitchLogEntry>("/api/v1/emergency/kill-switch/deactivate", {
      scope,
    });
  }
}
