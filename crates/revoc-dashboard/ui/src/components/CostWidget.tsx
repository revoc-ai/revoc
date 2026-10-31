interface Spender { service: string; cost_usd: number }

interface Props { costs: Spender[]; total: number }

export function CostWidget({ costs, total }: Props) {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
      <h3 className="mb-3 font-semibold text-gray-700">Estimated Cost (24 h)</h3>
      <p className="text-2xl font-bold text-gray-900">${total.toFixed(4)}</p>
      <ul className="mt-3 space-y-1 text-sm">
        {costs.slice(0, 5).map((c) => (
          <li key={c.service} className="flex justify-between text-gray-600">
            <span className="truncate max-w-[140px]">{c.service}</span>
            <span className="font-mono">${c.cost_usd.toFixed(4)}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
