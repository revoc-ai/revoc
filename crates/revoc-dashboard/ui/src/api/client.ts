import axios from 'axios'

const api = axios.create({ baseURL: '/dashboard/api' })

// ── Types ──────────────────────────────────────────────────────────────────────

export interface AuditEvent {
  id: string
  org_id: string | null
  request_id: string
  timestamp: string
  caller_id: string | null
  caller_team: string | null
  environment: string | null
  decision: string
  effective_action: string
  enforcement_mode: string
  violated_rules: string | null
  finding_types: string | null
  model: string | null
  provider: string | null
  tool_name: string | null
  request_type: string | null
  governance_depth: number
  prompt_tokens: number | null
  completion_tokens: number | null
  estimated_cost_usd: number | null
  duration_ms: number | null
  detection_ms: number | null
  policy_ms: number | null
  was_normalized: boolean
  manifest_warnings: number
  trace_id: string | null
  policy_engine: string | null
  created_at: string
}

export interface ListRequestsParams {
  decision?: string
  caller_id?: string
  start_time?: string
  end_time?: string
  trace_id?: string
  rule_id?: string
  limit?: number
  offset?: number
}

export interface PaginatedEvents {
  events: AuditEvent[]
  total: number
  limit: number
  offset: number
}

export interface AnalyticsResult {
  total: number
  blocked: number
  redacted: number
  allowed: number
  top_rules: Array<{ rule_id: string; count: number }>
  top_callers: Array<{ caller_id: string; count: number }>
  costs_by_service: Array<{ service: string; cost_usd: number }>
  timeline: Array<{ ts: string; total: number; blocked: number }>
}

export interface KillSwitchStatus {
  global: boolean
  by_org: Record<string, string>
  by_caller: Record<string, string>
}

export interface PolicyValidationResult {
  valid: boolean
  errors: string[]
}

export interface Rule {
  id: string
  entity: string
  action: string
  tier: string
  severity: string
  description: string
}

export interface GovernanceEvent {
  trace_id: string
  timestamp: string
  decision: string
  blocked_by: string | null
  caller_id: string
  model: string | null
  duration_ms: number
  findings_count: number
  pii_types: string[]
  mcp_tool: string | null
  request_type: string
  governance_depth: number
  was_normalized: boolean
  manifest_warnings: number
}

// ── API Functions ──────────────────────────────────────────────────────────────

export async function listRequests(params: ListRequestsParams): Promise<PaginatedEvents> {
  const { data } = await api.get<PaginatedEvents>('/requests', { params })
  return data
}

export async function getRequestDetail(traceId: string): Promise<AuditEvent> {
  const { data } = await api.get<AuditEvent>(`/requests/${traceId}`)
  return data
}

export async function getAnalytics(window: string): Promise<AnalyticsResult> {
  const { data } = await api.get<AnalyticsResult>('/analytics', { params: { window } })
  return data
}

export function getLiveFeed(onEvent: (e: GovernanceEvent) => void): () => void {
  const es = new EventSource('/dashboard/live')
  es.onmessage = (ev) => {
    try {
      onEvent(JSON.parse(ev.data) as GovernanceEvent)
    } catch {
      // ignore parse errors
    }
  }
  return () => es.close()
}

export async function getKillSwitchStatus(): Promise<KillSwitchStatus> {
  const { data } = await api.get<KillSwitchStatus>('/kill-switch/status')
  return data
}

export async function activateKillSwitch(scope: string, reason: string, target?: string): Promise<void> {
  await api.post('/kill-switch/activate', { scope, reason, target })
}

export async function deactivateKillSwitch(scope: string, target?: string): Promise<void> {
  await api.post('/kill-switch/deactivate', { scope, target })
}

export async function validatePolicy(yaml: string): Promise<PolicyValidationResult> {
  const { data } = await api.post<PolicyValidationResult>('/policies/validate', { yaml })
  return data
}

export async function getRules(): Promise<Rule[]> {
  const { data } = await api.get<Rule[]>('/rules')
  return data
}

export async function getCosts(window: string): Promise<AnalyticsResult['costs_by_service']> {
  const { data } = await api.get<AnalyticsResult['costs_by_service']>('/costs', { params: { window } })
  return data
}
