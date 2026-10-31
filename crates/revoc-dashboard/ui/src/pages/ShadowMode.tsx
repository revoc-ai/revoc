import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { listRequests, type AuditEvent } from '../api/client'

interface TimelineBucket {
  ts: string
  would_block: number
}

interface ShadowSummary {
  wouldBlock: number
  wouldRedact: number
  passThrough: number
  timeline: TimelineBucket[]
}

/// Number of most-recent audit events sampled to build the shadow-mode
/// preview. Large enough to give a representative picture without requiring
/// a dedicated server-side aggregation endpoint.
const SAMPLE_SIZE = 500

/// Bucket shadow-mode events into 4-hour windows (`HH:00`) by their raw
/// `decision` (the action that *would* have been taken under enforcement —
/// `effective_action` is always `audit` in shadow mode).
function summarize(events: AuditEvent[]): ShadowSummary {
  const shadowEvents = events.filter((e) => e.enforcement_mode === 'shadow')

  let wouldBlock = 0
  let wouldRedact = 0
  let passThrough = 0
  const buckets = new Map<string, number>()
  for (let h = 0; h < 24; h += 4) {
    buckets.set(`${String(h).padStart(2, '0')}:00`, 0)
  }

  for (const e of shadowEvents) {
    if (e.decision === 'block') wouldBlock += 1
    else if (e.decision === 'redact') wouldRedact += 1
    else passThrough += 1

    if (e.decision === 'block') {
      const hour = new Date(e.timestamp).getUTCHours()
      const bucketHour = hour - (hour % 4)
      const key = `${String(bucketHour).padStart(2, '0')}:00`
      buckets.set(key, (buckets.get(key) ?? 0) + 1)
    }
  }

  const timeline = Array.from(buckets.entries()).map(([ts, would_block]) => ({ ts, would_block }))

  return { wouldBlock, wouldRedact, passThrough, timeline }
}

export default function ShadowMode() {
  const [summary, setSummary] = useState<ShadowSummary | null>(null)
  const [sampledCount, setSampledCount] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      setError(null)
      try {
        const page = await listRequests({ limit: SAMPLE_SIZE, offset: 0 })
        if (cancelled) return
        setSampledCount(page.events.length)
        setSummary(summarize(page.events))
      } catch {
        if (!cancelled) setError('Failed to load shadow-mode data from the audit log.')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    void load()
    return () => { cancelled = true }
  }, [])

  const stats = summary
    ? [
        { label: 'Would block', value: summary.wouldBlock, color: 'text-red-600' },
        { label: 'Would redact', value: summary.wouldRedact, color: 'text-amber-600' },
        { label: 'Pass through', value: summary.passThrough, color: 'text-green-600' },
      ]
    : []

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-gray-800">Shadow Mode</h2>
        <span className="rounded bg-purple-100 px-3 py-1 text-sm font-medium text-purple-700">
          Observe-only — enforcement disabled
        </span>
      </div>

      <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-amber-800 text-sm">
        Shadow mode records governance decisions without blocking traffic. Use this to preview
        the impact of new rules before enabling enforcement.
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div>
      )}

      {!error && !loading && summary && summary.timeline.every((b) => b.would_block === 0) && summary.wouldBlock === 0 && summary.wouldRedact === 0 && summary.passThrough === 0 && (
        <div className="rounded-lg border border-gray-200 bg-white p-4 text-sm text-gray-500">
          No shadow-mode traffic recorded yet. Switch a caller's enforcement mode to{' '}
          <code className="rounded bg-gray-100 px-1 py-0.5">shadow</code> to start collecting a preview.
        </div>
      )}

      <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
        <h3 className="mb-4 font-semibold text-gray-700">
          Would-Be-Blocked {sampledCount > 0 ? `(last ${sampledCount} requests)` : ''}
        </h3>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={summary?.timeline ?? []}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
            <XAxis dataKey="ts" tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
            <Tooltip />
            <Bar dataKey="would_block" fill="#a855f7" radius={[4, 4, 0, 0]} name="Would block" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {(loading ? [{ label: 'Would block', value: '—', color: 'text-gray-400' }, { label: 'Would redact', value: '—', color: 'text-gray-400' }, { label: 'Pass through', value: '—', color: 'text-gray-400' }] : stats).map((s) => (
          <div key={s.label} className="rounded-lg border border-gray-200 bg-white p-4 text-center shadow-sm">
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            <p className="text-sm text-gray-500">{s.label}</p>
          </div>
        ))}
      </div>

      <Link
        to="/policies"
        className="inline-block rounded-lg bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-indigo-700"
      >
        Enable Enforcement →
      </Link>
    </div>
  )
}
