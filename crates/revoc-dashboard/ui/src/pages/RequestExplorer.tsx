import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { listRequests, AuditEvent } from '../api/client'
import { DecisionBadge } from '../components/DecisionBadge'

const DECISIONS = ['', 'block', 'redact', 'allow', 'audit']
const PAGE_SIZE = 25

export default function RequestExplorer() {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [decision, setDecision] = useState('')
  const [caller, setCaller] = useState('')
  const [ruleId, setRuleId] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setLoading(true)
    listRequests({
      decision: decision || undefined,
      caller_id: caller || undefined,
      rule_id: ruleId || undefined,
      limit: PAGE_SIZE,
      offset,
    })
      .then((r) => { setEvents(r.events); setTotal(r.total) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [decision, caller, ruleId, offset])

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold text-gray-800">Request Explorer</h2>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select
          className="rounded border border-gray-300 px-3 py-1.5 text-sm"
          value={decision}
          onChange={(e) => { setDecision(e.target.value); setOffset(0) }}
        >
          {DECISIONS.map((d) => <option key={d} value={d}>{d || 'All decisions'}</option>)}
        </select>
        <input
          className="rounded border border-gray-300 px-3 py-1.5 text-sm w-44"
          placeholder="Caller ID…"
          value={caller}
          onChange={(e) => { setCaller(e.target.value); setOffset(0) }}
        />
        <input
          className="rounded border border-gray-300 px-3 py-1.5 text-sm w-48"
          placeholder="Rule ID…"
          value={ruleId}
          onChange={(e) => { setRuleId(e.target.value); setOffset(0) }}
        />
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white shadow-sm">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 text-gray-600 text-xs uppercase tracking-wide">
            <tr>
              <th className="px-4 py-3 text-left">Decision</th>
              <th className="px-4 py-3 text-left">Caller</th>
              <th className="px-4 py-3 text-left">Model</th>
              <th className="px-4 py-3 text-left">Duration</th>
              <th className="px-4 py-3 text-left">Rules</th>
              <th className="px-4 py-3 text-left">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {loading && (
              <tr><td colSpan={6} className="py-8 text-center text-gray-400">Loading…</td></tr>
            )}
            {!loading && events.length === 0 && (
              <tr><td colSpan={6} className="py-8 text-center text-gray-400">No results</td></tr>
            )}
            {events.map((e) => (
              <tr
                key={e.id}
                className="hover:bg-gray-50 cursor-pointer"
                onClick={() => {}}
              >
                <td className="px-4 py-2.5">
                  <Link to={`/requests/${e.trace_id ?? e.id}`}>
                    <DecisionBadge decision={e.effective_action} />
                  </Link>
                </td>
                <td className="px-4 py-2.5 max-w-[120px] truncate text-gray-600">{e.caller_id ?? '—'}</td>
                <td className="px-4 py-2.5 text-gray-500">{e.model ?? '—'}</td>
                <td className="px-4 py-2.5 text-gray-500 font-mono text-xs">
                  {e.duration_ms != null ? `${e.duration_ms.toFixed(0)}ms` : '—'}
                </td>
                <td className="px-4 py-2.5 max-w-[160px] truncate text-xs text-gray-500">
                  {e.violated_rules ?? '—'}
                </td>
                <td className="px-4 py-2.5 text-gray-400 text-xs whitespace-nowrap">
                  {new Date(e.timestamp).toLocaleTimeString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm text-gray-500">
        <span>{total} total</span>
        <div className="flex gap-2">
          <button
            className="rounded border px-3 py-1 disabled:opacity-40"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          >← Prev</button>
          <button
            className="rounded border px-3 py-1 disabled:opacity-40"
            disabled={offset + PAGE_SIZE >= total}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >Next →</button>
        </div>
      </div>
    </div>
  )
}
