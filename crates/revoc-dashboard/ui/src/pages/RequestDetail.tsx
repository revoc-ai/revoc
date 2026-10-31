import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getRequestDetail, AuditEvent } from '../api/client'
import { DecisionBadge } from '../components/DecisionBadge'

function TimingBar({ label, ms, total }: { label: string; ms: number | null; total: number }) {
  const pct = total > 0 && ms ? Math.round((ms / total) * 100) : 0
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs text-gray-500">
        <span>{label}</span>
        <span>{ms != null ? `${ms.toFixed(1)}ms` : '—'}</span>
      </div>
      <div className="h-2 rounded bg-gray-100">
        <div className="h-2 rounded bg-blue-400" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

function InfoRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3 border-b border-gray-50 py-2 text-sm last:border-0">
      <span className="w-40 flex-shrink-0 font-medium text-gray-500">{label}</span>
      <span className="text-gray-800">{children}</span>
    </div>
  )
}

export default function RequestDetail() {
  const { traceId } = useParams<{ traceId: string }>()
  const [event, setEvent] = useState<AuditEvent | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!traceId) return
    getRequestDetail(traceId)
      .then(setEvent)
      .catch(() => setError('Event not found. It may have expired or the trace ID is incorrect.'))
  }, [traceId])

  if (error) return <div className="rounded-lg bg-red-50 p-8 text-red-700">{error}</div>
  if (!event) return <div className="p-8 text-gray-400">Loading…</div>

  const violatedRules = event.violated_rules?.split(',').filter(Boolean) ?? []
  const findingTypes = event.finding_types?.split(',').filter(Boolean) ?? []
  const totalMs = event.duration_ms ?? 1
  const isBlock = event.effective_action === 'block'

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <div className="flex items-center gap-4">
        <Link to="/requests" className="text-blue-600 hover:underline text-sm">← All requests</Link>
        <code className="text-xs text-gray-400">{traceId}</code>
      </div>

      {/* ── Hero — answers "why was this blocked?" in 5 seconds ── */}
      <div className={`rounded-xl border-2 p-6 ${isBlock ? 'border-red-300 bg-red-50' : 'border-gray-200 bg-white'}`}>
        <div className="flex items-start gap-6">
          <DecisionBadge decision={event.effective_action} size="lg" />
          <div className="flex-1 space-y-2">
            {violatedRules[0] && (
              <p className="text-lg font-semibold text-gray-900">
                Rule: <code className="rounded bg-gray-100 px-2 py-0.5 text-base">{violatedRules[0]}</code>
              </p>
            )}
            {event.enforcement_mode === 'shadow' && (
              <span className="inline-block rounded bg-purple-100 px-2 py-0.5 text-xs font-medium text-purple-700">
                Shadow mode — not enforced
              </span>
            )}
            {violatedRules.length > 0 && (
              <a
                href={`https://revoc.io/docs/policies/${violatedRules[0]}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-block text-sm text-blue-600 hover:underline"
              >
                📖 View rule documentation →
              </a>
            )}
          </div>
        </div>
      </div>

      {/* ── Evasion / Manifest warnings ── */}
      <div className="flex gap-3">
        {event.was_normalized && (
          <div className="rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-amber-800 text-sm font-medium">
            ⚠️ Evasion attempt detected — input was Unicode-normalized before matching
          </div>
        )}
        {event.manifest_warnings > 0 && (
          <div className="rounded-lg border border-orange-300 bg-orange-50 px-4 py-3 text-orange-800 text-sm font-medium">
            🔍 {event.manifest_warnings} tool manifest warning{event.manifest_warnings !== 1 ? 's' : ''}
          </div>
        )}
        {event.governance_depth > 0 && (
          <div className="rounded-lg border border-gray-200 bg-gray-50 px-4 py-3 text-gray-700 text-sm">
            Governance depth: <strong>{event.governance_depth}</strong> / 10
          </div>
        )}
      </div>

      {/* ── Findings ── */}
      {findingTypes.length > 0 && (
        <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
          <h3 className="mb-3 font-semibold text-gray-700">Findings ({findingTypes.length})</h3>
          <div className="flex flex-wrap gap-2">
            {findingTypes.map((ft, i) => (
              <span key={i} className="rounded border border-red-200 bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700">
                {ft}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── Duration breakdown ── */}
      <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
        <h3 className="mb-4 font-semibold text-gray-700">Timing Breakdown</h3>
        <div className="space-y-3">
          <TimingBar label="Detection" ms={event.detection_ms} total={totalMs} />
          <TimingBar label="Policy evaluation" ms={event.policy_ms} total={totalMs} />
          <TimingBar label="Total" ms={event.duration_ms} total={totalMs} />
        </div>
        <p className="mt-3 text-xs text-gray-400">
          Upstream latency is excluded from the total — see X-Revoc-Timing header for full breakdown.
        </p>
      </div>

      {/* ── Caller + metadata ── */}
      <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
        <h3 className="mb-2 font-semibold text-gray-700">Request Metadata</h3>
        <InfoRow label="Caller ID">{event.caller_id ?? '—'}</InfoRow>
        <InfoRow label="Team">{event.caller_team ?? '—'}</InfoRow>
        <InfoRow label="Environment">{event.environment ?? '—'}</InfoRow>
        <InfoRow label="Model">{event.model ?? '—'}</InfoRow>
        <InfoRow label="Provider">{event.provider ?? '—'}</InfoRow>
        <InfoRow label="Request type">{event.request_type ?? '—'}</InfoRow>
        {event.tool_name && <InfoRow label="MCP tool">{event.tool_name}</InfoRow>}
        <InfoRow label="Policy engine">{event.policy_engine ?? '—'}</InfoRow>
        <InfoRow label="Timestamp">{new Date(event.timestamp).toLocaleString()}</InfoRow>
        {event.estimated_cost_usd != null && (
          <InfoRow label="Estimated cost">${event.estimated_cost_usd.toFixed(6)}</InfoRow>
        )}
        {event.prompt_tokens != null && (
          <InfoRow label="Tokens">
            {event.prompt_tokens.toLocaleString()} prompt / {event.completion_tokens?.toLocaleString() ?? '?'} completion
          </InfoRow>
        )}
        {violatedRules.length > 1 && (
          <InfoRow label="All violated rules">
            <div className="flex flex-wrap gap-1">
              {violatedRules.map((r, i) => (
                <code key={i} className="rounded bg-gray-100 px-1 text-xs">{r}</code>
              ))}
            </div>
          </InfoRow>
        )}
      </div>
    </div>
  )
}
