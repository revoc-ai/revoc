import { useEffect, useState } from 'react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { getAnalytics, getKillSwitchStatus, AnalyticsResult, KillSwitchStatus } from '../api/client'
import { LiveFeed } from '../components/LiveFeed'
import { CostWidget } from '../components/CostWidget'

const PIE_COLORS = { block: '#ef4444', redact: '#f59e0b', allow: '#22c55e', audit: '#3b82f6' }

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className={`rounded-lg border-l-4 bg-white p-4 shadow-sm ${color}`}>
      <p className="text-sm text-gray-500">{label}</p>
      <p className="text-2xl font-bold text-gray-900">{value.toLocaleString()}</p>
    </div>
  )
}

export default function Overview() {
  const [analytics, setAnalytics] = useState<AnalyticsResult | null>(null)
  const [ks, setKs] = useState<KillSwitchStatus | null>(null)

  useEffect(() => {
    getAnalytics('24h').then(setAnalytics).catch(console.error)
    getKillSwitchStatus().then(setKs).catch(console.error)
  }, [])

  const pieData = analytics
    ? [
        { name: 'Blocked', value: analytics.blocked, fill: PIE_COLORS.block },
        { name: 'Redacted', value: analytics.redacted, fill: PIE_COLORS.redact },
        { name: 'Allowed', value: analytics.allowed, fill: PIE_COLORS.allow },
      ]
    : []

  const totalCost = analytics?.costs_by_service.reduce((s, c) => s + c.cost_usd, 0) ?? 0

  return (
    <div className="space-y-6">
      {ks?.global && (
        <div className="rounded-lg bg-red-600 px-6 py-4 text-white font-semibold text-lg flex items-center gap-3">
          🚨 Emergency Kill-Switch is ACTIVE — all AI traffic is blocked
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Total (24h)" value={analytics?.total ?? 0} color="border-gray-300" />
        <StatCard label="Blocked" value={analytics?.blocked ?? 0} color="border-red-500" />
        <StatCard label="Redacted" value={analytics?.redacted ?? 0} color="border-amber-500" />
        <StatCard label="Allowed" value={analytics?.allowed ?? 0} color="border-green-500" />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <LiveFeed />
        </div>
        <div className="space-y-4">
          <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
            <h3 className="mb-2 font-semibold text-gray-700">Decision Distribution</h3>
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" outerRadius={70}>
                  {pieData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <CostWidget costs={analytics?.costs_by_service ?? []} total={totalCost} />
        </div>
      </div>

      <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
        <h3 className="mb-3 font-semibold text-gray-700">Governance Depth Indicator</h3>
        <p className="text-sm text-gray-500">
          Maximum depth seen: depth limit is <strong>10</strong>. Requests at depth ≥ 10 are
          rejected immediately with HTTP 503.
        </p>
      </div>
    </div>
  )
}
