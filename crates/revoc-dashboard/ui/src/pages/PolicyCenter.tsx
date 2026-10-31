import { useState } from 'react'
import { validatePolicy } from '../api/client'

export default function PolicyCenter() {
  const [yaml, setYaml] = useState('')
  const [errors, setErrors] = useState<string[]>([])
  const [valid, setValid] = useState<boolean | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleValidate() {
    setLoading(true)
    try {
      const result = await validatePolicy(yaml)
      setValid(result.valid)
      setErrors(result.errors)
    } catch {
      setErrors(['Failed to reach validation endpoint'])
      setValid(false)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4 max-w-3xl">
      <h2 className="text-xl font-semibold text-gray-800">Policy Center</h2>

      <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
        <h3 className="mb-2 font-semibold text-gray-700">Policy Editor</h3>
        <p className="mb-3 text-sm text-gray-500">
          Paste a YAML policy bundle to validate. Changes take effect after activation via the Admin API.
        </p>
        <textarea
          className="w-full rounded border border-gray-300 font-mono text-sm p-3 h-64 focus:border-blue-400 focus:outline-none"
          placeholder="# Paste your policy YAML here..."
          value={yaml}
          onChange={(e) => setYaml(e.target.value)}
        />
        <div className="mt-3 flex items-center gap-3">
          <button
            onClick={handleValidate}
            disabled={loading || yaml.trim().length === 0}
            className="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-40"
          >
            {loading ? 'Validating…' : 'Validate Policy'}
          </button>
          {valid === true && <span className="text-sm font-medium text-green-600">✓ Valid</span>}
          {valid === false && <span className="text-sm font-medium text-red-600">✗ Invalid</span>}
        </div>
        {errors.length > 0 && (
          <ul className="mt-3 space-y-1 rounded bg-red-50 p-3 text-sm text-red-700">
            {errors.map((e, i) => <li key={i}>• {e}</li>)}
          </ul>
        )}
      </div>
    </div>
  )
}
