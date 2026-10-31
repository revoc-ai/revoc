import { useEffect, useState } from 'react'
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid, Legend
} from 'recharts'
import { getAnalytics, AnalyticsResult } from '../api/client'

const WINDOWS = ['1h', '24h', '7d', '30d'] as const
type Window = typeof WINDOWS[number]

export default function Analytics() {
  const [window, setWindow] = useState<Window>('24h')
  const [data, setData] = useState<AnalyticsResult | null>(null)

  useEffect(() => {
    getAnalytics(window).then(setData).catch(console.error)
  }, [window])

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <h2 className="text-xl font-semibold text-gray-800">Analytics</h2>
        <div className="flex gap-1 rounded-lg border border-gray-200 p-1">
          {WINDOWS.map((w) => (
            <button
              key={w}
              onClick={() => setWindow(w)}
              className={`rounded px-3 py-1 text-sm font-medium transition ${
                window === w ? 'bg-blue-600 text-white' : 'text-gray-600 hover:bg-gray-100'
              }`}
            >{w}</button>
          ))}
        </div>
      </div>

      {/* Requests timeline */}
      <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
        <h3 className="mb-4 font-semibold text-gray-700">Requests Timeline</h3>
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={data?.timeline ?? []}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
            <XAxis dataKey="ts" tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} />
            <Tooltip />
            <Legend />
            <Line type="monotone" dataKey="total" stroke="#6366f1" strokeWidth={2} dot={false} name="Total" />
            <Line type="monotone" dataKey="blocked" stroke="#ef4444" strokeWidth={2} dot={false} name="Blocked" />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Top rules */}
        <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
          <h3 className="mb-4 font-semibold text-gray-700">Top Rules</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={data?.top_rules?.slice(0, 8) ?? []} layout="vertical">
              <XAxis type="number" tick={{ fontSize: 11 }} />
              <YAxis dataKey="rule_id" type="category" tick={{ fontSize: 10 }} width={140} />
              <Tooltip />
              <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Top callers */}
        <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
          <h3 className="mb-4 font-semibold text-gray-700">Top Callers</h3>
          <table className="w-full text-sm">
            <thead className="text-xs text-gray-500 uppercase">
              <tr>
                <th className="pb-2 text-left">Caller</th>
                <th className="pb-2 text-right">Requests</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {(data?.top_callers ?? []).slice(0, 8).map((c) => (
                <tr key={c.caller_id}>
                  <td className="py-1.5 truncate max-w-[180px] text-gray-700">{c.caller_id}</td>
                  <td className="py-1.5 text-right font-mono text-gray-500">{c.count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Cost by service */}
      <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
        <h3 className="mb-3 font-semibold text-gray-700">Cost by Service</h3>
        <table className="w-full text-sm">
          <thead className="text-xs text-gray-500 uppercase">
            <tr>
              <th className="pb-2 text-left">Service</th>
              <th className="pb-2 text-right">Cost (USD)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {(data?.costs_by_service ?? []).map((c) => (
              <tr key={c.service}>
                <td className="py-1.5 text-gray-700">{c.service}</td>
                <td className="py-1.5 text-right font-mono text-gray-500">${c.cost_usd.toFixed(4)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
