import { useEffect, useRef, useState } from 'react'
import { getLiveFeed, GovernanceEvent } from '../api/client'
import { DecisionBadge } from './DecisionBadge'

export function LiveFeed() {
  const [events, setEvents] = useState<GovernanceEvent[]>([])
  const [paused, setPaused] = useState(false)
  const pausedRef = useRef(paused)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => { pausedRef.current = paused }, [paused])

  useEffect(() => {
    const close = getLiveFeed((e) => {
      if (!pausedRef.current) {
        setEvents((prev) => [e, ...prev].slice(0, 20))
      }
    })
    return close
  }, [])

  useEffect(() => {
    if (!paused) bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [events, paused])

  return (
    <div
      className="rounded-lg border border-gray-200 bg-white shadow-sm"
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
    >
      <div className="flex items-center justify-between border-b px-4 py-2">
        <h3 className="font-semibold text-gray-700">Live Feed</h3>
        {paused && <span className="text-xs text-gray-400">Paused</span>}
      </div>
      <div className="max-h-72 overflow-y-auto divide-y divide-gray-50 text-sm">
        {events.length === 0 && (
          <p className="px-4 py-6 text-center text-gray-400">Waiting for events…</p>
        )}
        {events.map((e, i) => (
          <div key={i} className="flex items-center gap-3 px-4 py-2 hover:bg-gray-50">
            <DecisionBadge decision={e.decision} />
            <span className="flex-1 truncate text-gray-600">{e.caller_id}</span>
            {e.was_normalized && <span title="Evasion detected" className="text-amber-500 text-xs">⚠️</span>}
            <span className="text-gray-400 text-xs whitespace-nowrap">
              {new Date(e.timestamp).toLocaleTimeString()}
            </span>
          </div>
        ))}
      </div>
      <div ref={bottomRef} />
    </div>
  )
}
