interface Props { decision: string; size?: 'sm' | 'lg' }

const COLORS: Record<string, string> = {
  block:        'bg-red-100 text-red-800 border-red-300',
  'shadow-block': 'bg-purple-100 text-purple-800 border-purple-300',
  redact:       'bg-amber-100 text-amber-800 border-amber-300',
  allow:        'bg-green-100 text-green-800 border-green-300',
  audit:        'bg-blue-100 text-blue-800 border-blue-300',
}

export function DecisionBadge({ decision, size = 'sm' }: Props) {
  const cls = COLORS[decision.toLowerCase()] ?? 'bg-gray-100 text-gray-700 border-gray-300'
  const text = size === 'lg'
    ? 'text-2xl font-bold px-6 py-3 rounded-xl border-2'
    : 'text-xs font-semibold px-2 py-0.5 rounded border'
  return <span className={`${cls} ${text} uppercase tracking-wide`}>{decision}</span>
}
